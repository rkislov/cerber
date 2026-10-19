package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rkislov/cerber/internal/knowledge"
)

const cliTestToken = "cli-integration-test-token-123456789"

func TestCLIKnowledgeAndTaskIntegration(t *testing.T) {
	root := t.TempDir()
	keys := filepath.Join(root, "keys")
	repoPath := filepath.Join(root, "repo")
	cache := filepath.Join(root, "cache")
	db := filepath.Join(root, "db")
	t.Setenv("CERBER_KNOWLEDGE_TOKEN", cliTestToken)
	call := func(args ...string) map[string]any {
		t.Helper()
		var out, errOut bytes.Buffer
		if err := run(context.Background(), append([]string{"-db", db}, args...), &out, &errOut); err != nil {
			t.Fatalf("%v: %v %s", args, err, errOut.String())
		}
		var result map[string]any
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	call("knowledge", "keygen", "-dir", keys)
	if _, err := os.Stat(db); !os.IsNotExist(err) {
		t.Fatal("knowledge commands opened scan database", err)
	}
	xml := filepath.Join(root, "input.xml")
	if err := os.WriteFile(xml, []byte(`<vulnerabilities/>`), 0600); err != nil {
		t.Fatal(err)
	}
	manifest := call("knowledge", "publish", "-file", xml, "-version", "test.1", "-private-key", filepath.Join(keys, "signing.key"), "-repo", repoPath)
	handler, err := knowledge.NewHandler(knowledge.Repository{Root: repoPath}, cliTestToken)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	call("knowledge", "sync", "-server", server.URL, "-public-key", filepath.Join(keys, "signing.pub"), "-cache", cache)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	asset := call("asset", "add", "-ip", "127.0.0.1")
	target := call("target", "add", "-name", "central knowledge", "-assets", asset["id"].(string))
	task := call("task", "create", "-target", target["id"].(string), "-ports", fmt.Sprint(ln.Addr().(*net.TCPAddr).Port))
	result := call("task", "run", "-id", task["id"].(string), "-knowledge-server", server.URL, "-knowledge-key", filepath.Join(keys, "signing.pub"), "-knowledge-cache", cache)
	stored := result["task"].(map[string]any)
	if stored["status"] != "completed" || stored["knowledge_snapshot"].(map[string]any)["sha256"] != manifest["snapshot"].(map[string]any)["sha256"] {
		t.Fatal(result)
	}
	server.Close()
	call("knowledge", "sync", "-offline", "-public-key", filepath.Join(keys, "signing.pub"), "-cache", cache)
}

type readyWriter chan string

func (w readyWriter) Write(b []byte) (int, error) { w <- string(b); return len(b), nil }
func TestKnowledgeServerReadinessAndShutdown(t *testing.T) {
	root := t.TempDir()
	keys := filepath.Join(root, "keys")
	if err := knowledge.GenerateKeys(keys); err != nil {
		t.Fatal(err)
	}
	key, err := knowledge.ReadPrivateKey(filepath.Join(keys, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	repo := knowledge.Repository{Root: filepath.Join(root, "repo")}
	if _, err := repo.Publish(context.Background(), strings.NewReader(`<vulnerabilities/>`), "test.1", "test", key); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(readyWriter, 1)
	done := make(chan error, 1)
	go func() { done <- serveKnowledge(ctx, repo.Root, "127.0.0.1:0", "", "", cliTestToken, ready) }()
	var addr string
	select {
	case line := <-ready:
		addr = strings.TrimSpace(strings.TrimPrefix(line, "knowledge repository listening on "))
	case <-time.After(5 * time.Second):
		t.Fatal("no readiness")
	}
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/v1/knowledge/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+cliTestToken)
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}
func TestKnowledgeServerRefusesUnsafeListenAndMissingAuth(t *testing.T) {
	for _, tc := range []struct{ listen, cert, key, token string }{
		{"0.0.0.0:0", "", "", cliTestToken},
		{"localhost:0", "", "", cliTestToken},
		{"127.0.0.1:0", "", "", ""},
		{"127.0.0.1:0", "missing.crt", "", cliTestToken},
		{"0.0.0.0:0", "missing.crt", "missing.key", cliTestToken},
	} {
		if err := serveKnowledge(context.Background(), t.TempDir(), tc.listen, tc.cert, tc.key, tc.token, io.Discard); err == nil {
			t.Fatal("unsafe server configuration accepted")
		}
	}
}
func TestUpstreamRejectsUnsafeURL(t *testing.T) {
	for _, raw := range []string{"http://example.com/bdu.xml", "file:///tmp/x", "https://user:password@example.com/bdu.xml", "https://example.com/bdu.xml?secret=x"} {
		if body, err := fetchUpstream(context.Background(), raw); err == nil {
			body.Close()
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestKnowledgeServerTLSListener(t *testing.T) {
	// Reuse httptest's test certificate and trust roots; the server under test is
	// serveKnowledge itself, not httptest's listener.
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	client := fixture.Client()
	pair := fixture.TLS.Certificates[0]
	fixture.Close()
	root := t.TempDir()
	cert := filepath.Join(root, "tls.crt")
	key := filepath.Join(root, "tls.key")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(readyWriter, 1)
	done := make(chan error, 1)
	go func() { done <- serveKnowledge(ctx, root, "127.0.0.1:0", cert, key, cliTestToken, ready) }()
	var addr string
	select {
	case line := <-ready:
		addr = strings.TrimSpace(strings.TrimPrefix(line, "knowledge repository listening on "))
	case <-time.After(5 * time.Second):
		t.Fatal("TLS listener did not start")
	}
	request, err := http.NewRequest(http.MethodGet, "https://"+addr+"/v1/knowledge/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+cliTestToken)
	client.Timeout = 5 * time.Second
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	// Empty repository is expected; a successful verified TLS connection and an
	// authenticated application response prove the loaded certificate is used.
	if response.StatusCode != http.StatusServiceUnavailable || response.TLS == nil {
		t.Fatal(response.Status)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TLS shutdown hung")
	}
}
