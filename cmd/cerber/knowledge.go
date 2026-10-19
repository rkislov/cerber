// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"time"

	"github.com/rkislov/cerber/internal/knowledge"
)

func knowledgeCommand(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) < 1 {
		return fmt.Errorf("knowledge command required")
	}
	f := flags("knowledge "+args[0], errOut)
	var result any
	switch args[0] {
	case "keygen":
		dir := f.String("dir", ".local/knowledge-keys", "key directory")
		if err := parse(f, args[1:]); err != nil {
			return err
		}
		if err := knowledge.GenerateKeys(*dir); err != nil {
			return err
		}
		result = map[string]string{"keys_directory": *dir}
	case "publish":
		repo := f.String("repo", ".local/knowledge-repo", "repository directory")
		file := f.String("file", "", "offline XML file")
		upstream := f.String("url", "", "upstream HTTPS XML URL (alternative to -file)")
		version := f.String("version", "", "unique package version")
		key := f.String("private-key", "", "base64 Ed25519 seed file")
		if err := parse(f, args[1:]); err != nil {
			return err
		}
		if (*file == "") == (*upstream == "") {
			return fmt.Errorf("specify exactly one of -file or -url")
		}
		private, err := knowledge.ReadPrivateKey(*key)
		if err != nil {
			return err
		}
		var input io.ReadCloser
		source := "offline-import"
		if *file != "" {
			input, err = os.Open(*file)
		} else {
			input, err = fetchUpstream(ctx, *upstream)
			source = *upstream
		}
		if err != nil {
			return err
		}
		defer input.Close()
		result, err = (knowledge.Repository{Root: *repo}).Publish(ctx, input, *version, source, private)
		if err != nil {
			return err
		}
	case "sync":
		server := f.String("server", "", "knowledge server origin")
		pub := f.String("public-key", "", "trusted public key file")
		cache := f.String("cache", ".local/knowledge-cache", "cache directory")
		maxAge := f.Duration("max-age", 72*time.Hour, "maximum manifest age")
		offline := f.Bool("offline", false, "verify and use local cache only")
		if err := parse(f, args[1:]); err != nil {
			return err
		}
		key, err := knowledge.ReadPublicKey(*pub)
		if err != nil {
			return err
		}
		result, err = (knowledge.Provider{URL: *server, Token: os.Getenv("CERBER_KNOWLEDGE_TOKEN"), PublicKey: key, CacheDir: *cache, MaxAge: *maxAge, Offline: *offline}).Sync(ctx)
		if err != nil {
			return err
		}
	case "serve":
		repo := f.String("repo", ".local/knowledge-repo", "repository directory")
		listen := f.String("listen", "127.0.0.1:8787", "listen address")
		cert := f.String("tls-cert", "", "TLS certificate file")
		key := f.String("tls-key", "", "TLS private key file")
		if err := parse(f, args[1:]); err != nil {
			return err
		}
		return serveKnowledge(ctx, *repo, *listen, *cert, *key, os.Getenv("CERBER_KNOWLEDGE_TOKEN"), errOut)
	default:
		return fmt.Errorf("unknown knowledge command %q", args[0])
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
func fetchUpstream(ctx context.Context, rawURL string) (io.ReadCloser, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("upstream must be an HTTPS URL without credentials, query or fragment")
	}
	client := http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, fmt.Errorf("upstream returned HTTP %d", response.StatusCode)
	}
	return response.Body, nil
}
func serveKnowledge(ctx context.Context, repo, listen, cert, key, token string, errOut io.Writer) error {
	if (cert == "") != (key == "") {
		return fmt.Errorf("both TLS certificate and key are required")
	}
	if cert == "" {
		host, _, err := net.SplitHostPort(listen)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Unmap().IsLoopback() {
			return fmt.Errorf("plaintext listener requires an explicit loopback IP; use TLS for network access")
		}
	}
	handler, err := knowledge.NewHandler(knowledge.Repository{Root: repo}, token)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, WriteTimeout: 10 * time.Minute, MaxHeaderBytes: 16 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	// Validate TLS files before opening a socket or reporting readiness.
	if cert != "" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return err
		}
		server.TLSConfig.Certificates = []tls.Certificate{pair}
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Fprintf(errOut, "knowledge repository listening on %s\n", listener.Addr())
	done := make(chan error, 1)
	go func() {
		if cert != "" {
			done <- server.ServeTLS(listener, "", "")
		} else {
			done <- server.Serve(listener)
		}
	}()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := server.Shutdown(shutdown)
		if err != nil {
			server.Close()
		}
		<-done
		return err
	}
}
