package knowledge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "cerber-test-token-not-a-secret-123456"

func setup(t *testing.T) (Repository, ed25519.PublicKey, ed25519.PrivateKey, Manifest) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{Root: t.TempDir()}
	m, err := repo.Publish(context.Background(), strings.NewReader(`<vulnerabilities><vulnerability id="BDU:TEST"/></vulnerabilities>`), "2026.10.19", "offline-test", key)
	if err != nil {
		t.Fatal(err)
	}
	return repo, pub, key, m
}
func server(t *testing.T, repo Repository) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	handler, err := NewHandler(repo, testToken)
	if err != nil {
		t.Fatal(err)
	}
	count := new(atomic.Int32)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/knowledge/packages/") {
			count.Add(1)
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s, count
}
func provider(t *testing.T, s *httptest.Server, pub ed25519.PublicKey) Provider {
	t.Helper()
	return Provider{URL: s.URL, Token: testToken, PublicKey: pub, CacheDir: t.TempDir(), MaxAge: 72 * time.Hour}
}
func TestSignedDistributionCacheAndOffline(t *testing.T) {
	repo, pub, _, manifest := setup(t)
	s, count := server(t, repo)
	p := provider(t, s, pub)
	for i := 0; i < 2; i++ {
		snapshot, err := p.Acquire(context.Background())
		if err != nil || snapshot != manifest.Snapshot {
			t.Fatal(snapshot, err)
		}
	}
	if count.Load() != 1 {
		t.Fatalf("same package downloaded %d times", count.Load())
	}
	s.Close()
	p.Offline = true
	got, err := p.Acquire(context.Background())
	if err != nil || got != manifest.Snapshot {
		t.Fatal(got, err)
	}
	p.Offline = false
	if _, err = p.Acquire(context.Background()); err == nil {
		t.Fatal("online failure silently fell back to cache")
	}
}
func TestRejectsWrongKeyAndTamperedManifest(t *testing.T) {
	repo, pub, _, _ := setup(t)
	data, err := repo.Latest()
	if err != nil {
		t.Fatal(err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err = Verify(data, other); err == nil {
		t.Fatal("wrong key accepted")
	}
	var signed SignedManifest
	if err = json.Unmarshal(data, &signed); err != nil {
		t.Fatal(err)
	}
	signed.Manifest = bytes.ReplaceAll(signed.Manifest, []byte("2026.10.19"), []byte("2026.10.20"))
	tampered, _ := json.Marshal(signed)
	if _, err = Verify(tampered, pub); err == nil {
		t.Fatal("tampered manifest accepted")
	}
	if _, err = Verify(data[:len(data)/2], pub); err == nil {
		t.Fatal("truncated manifest accepted")
	}
}
func TestCorruptDownloadDoesNotActivateCache(t *testing.T) {
	repo, pub, _, m := setup(t)
	s, _ := server(t, repo)
	p := provider(t, s, pub)
	if err := os.WriteFile(repo.packagePath(m.Snapshot.SHA256), []byte("<corrupt/>"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Sync(context.Background()); err == nil {
		t.Fatal("tampered blob accepted")
	}
	if _, err := os.Stat(filepath.Join(p.CacheDir, "latest.json")); !os.IsNotExist(err) {
		t.Fatal("invalid manifest activated", err)
	}
	files, err := os.ReadDir(filepath.Join(p.CacheDir, "packages"))
	if err != nil || len(files) != 0 {
		t.Fatal(files, err)
	}
}
func TestRepairsCorruptCacheAndRejectsOfflineCorruption(t *testing.T) {
	repo, pub, _, m := setup(t)
	s, count := server(t, repo)
	p := provider(t, s, pub)
	if _, err := p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(p.CacheDir, "packages", m.Snapshot.SHA256+".xml")
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	p.Offline = true
	if _, err := p.Sync(context.Background()); err == nil {
		t.Fatal("offline corruption accepted")
	}
	p.Offline = false
	if _, err := p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if count.Load() != 2 {
		t.Fatal("cache was not repaired", count.Load())
	}
}
func TestRollbackAndSequenceReuseRejected(t *testing.T) {
	repo, pub, key, _ := setup(t)
	s, _ := server(t, repo)
	p := provider(t, s, pub)
	old, err := repo.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	m, err := repo.Publish(context.Background(), strings.NewReader(`<next/>`), "2026.10.20", "offline-test", key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = writeAtomic(filepath.Join(repo.Root, "latest.json"), old); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Sync(context.Background()); err == nil {
		t.Fatal("rollback accepted")
	}
	m.Source = "changed-but-same-sequence"
	changed, err := Sign(m, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeAtomic(filepath.Join(repo.Root, "latest.json"), changed); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Sync(context.Background()); err == nil {
		t.Fatal("sequence reuse accepted")
	}
	p.Offline = true
	cached, err := p.Sync(context.Background())
	if err != nil || cached.Snapshot != m.Snapshot {
		t.Fatal("good cache lost", cached, err)
	}
}
func TestFreshnessAndFutureManifest(t *testing.T) {
	repo, pub, key, m := setup(t)
	s, _ := server(t, repo)
	p := provider(t, s, pub)
	for _, at := range []time.Time{time.Now().Add(-80 * time.Hour), time.Now().Add(time.Hour)} {
		m.PublishedAt = at
		data, err := Sign(m, key)
		if err != nil {
			t.Fatal(err)
		}
		if err = writeAtomic(filepath.Join(repo.Root, "latest.json"), data); err != nil {
			t.Fatal(err)
		}
		if _, err = p.Sync(context.Background()); err == nil {
			t.Fatal("expired/future manifest accepted")
		}
	}
}
func TestPublishRejectsBadXMLAndDuplicateVersion(t *testing.T) {
	repo, _, key, m := setup(t)
	before, err := repo.Latest()
	if err != nil {
		t.Fatal(err)
	}
	inputs := []string{"", "text", "<one/><two/>", "<broken>", `<!DOCTYPE x><x/>`, strings.Repeat("<x>", 129) + strings.Repeat("</x>", 129)}
	for _, input := range inputs {
		if _, err := repo.Publish(context.Background(), strings.NewReader(input), "bad-version", "offline-test", key); err == nil {
			t.Fatalf("accepted bad XML %q", input[:min(len(input), 40)])
		}
	}
	if _, err := repo.Publish(context.Background(), strings.NewReader(`<x/>`), m.Snapshot.Version, "offline-test", key); err == nil {
		t.Fatal("version overwritten")
	}
	after, err := repo.Latest()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed publication changed active manifest", err)
	}
}
func TestAuthRedirectAndTransportPolicy(t *testing.T) {
	repo, pub, _, _ := setup(t)
	s, _ := server(t, repo)
	p := provider(t, s, pub)
	p.Token = strings.Repeat("x", 24)
	if _, err := p.Sync(context.Background()); err == nil {
		t.Fatal("bad auth accepted")
	}
	var reached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer redirect.Close()
	p.URL = redirect.URL
	p.Token = testToken
	if _, err := p.Sync(context.Background()); err == nil || reached.Load() != 0 {
		t.Fatal("credentials followed redirect", err)
	}
	for _, raw := range []string{"http://example.com", "http://localhost:8787", "https://user:secret@example.com", "https://example.com/path", "https://example.com/?token=secret", "file:///tmp/x"} {
		u, _ := url.Parse(raw)
		if err := ValidateURL(u); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
func TestCancellationAndLocking(t *testing.T) {
	repo, pub, key, _ := setup(t)
	s, _ := server(t, repo)
	p := provider(t, s, pub)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Sync(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	unlock, err := lock(repo.Root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Publish(context.Background(), strings.NewReader(`<x/>`), "locked", "offline-test", key); err == nil {
		t.Fatal("concurrent publisher accepted")
	}
	unlock()
	if _, err := repo.Publish(ctx, strings.NewReader(`<x/>`), "cancelled", "offline-test", key); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestKeyGenerationNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	if err := GenerateKeys(dir); err != nil {
		t.Fatal(err)
	}
	private, err := ReadPrivateKey(filepath.Join(dir, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ReadPublicKey(filepath.Join(dir, "signing.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if !private.Public().(ed25519.PublicKey).Equal(pub) {
		t.Fatal("keys do not match")
	}
	if err = GenerateKeys(dir); err == nil {
		t.Fatal("existing keys overwritten")
	}
}

func TestTLSAndRequestCancellation(t *testing.T) {
	repo, pub, _, m := setup(t)
	handler, err := NewHandler(repo, testToken)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewTLSServer(handler)
	defer s.Close()
	p := provider(t, s, pub)
	p.Client = s.Client()
	if got, err := p.Sync(context.Background()); err != nil || got.Snapshot != m.Snapshot {
		t.Fatal(got, err)
	}
	started := make(chan struct{})
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer blocked.Close()
	p.URL = blocked.URL
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := p.Sync(ctx); done <- err }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request cancellation hung")
	}
}
func TestManifestLimitsAndOfflineEmpty(t *testing.T) {
	_, pub, _, _ := setup(t)
	if _, err := Verify(bytes.Repeat([]byte("x"), int(MaxManifestBytes)+1), pub); err == nil {
		t.Fatal("oversized manifest accepted")
	}
	p := Provider{PublicKey: pub, CacheDir: t.TempDir(), MaxAge: 72 * time.Hour, Offline: true}
	if _, err := p.Sync(context.Background()); err == nil {
		t.Fatal("empty offline cache accepted")
	}
}

func TestNewManifestReusesVerifiedPayloadAndKeepsReleaseEvidence(t *testing.T) {
	repo, pub, key, first := setup(t)
	s, count := server(t, repo)
	p := provider(t, s, pub)
	if _, err := p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	original, err := os.Open(repo.packagePath(first.Snapshot.SHA256))
	if err != nil {
		t.Fatal(err)
	}
	second, err := repo.Publish(context.Background(), original, "2026.10.20", "offline-test", key)
	original.Close()
	if err != nil {
		t.Fatal(err)
	}
	if second.Sequence != first.Sequence+1 {
		t.Fatal("sequence did not advance")
	}
	if _, err := p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if count.Load() != 1 {
		t.Fatal("unchanged payload downloaded again")
	}
	for _, m := range []Manifest{first, second} {
		data, err := os.ReadFile(filepath.Join(p.CacheDir, "releases", m.Snapshot.Version+".json"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := Verify(data, pub)
		if err != nil || got != m {
			t.Fatal(got, err)
		}
	}
	// Even a signed manifest cannot silently reuse an old version with a newer sequence.
	second.Sequence++
	data, err := Sign(second, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeAtomic(filepath.Join(repo.Root, "latest.json"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Sync(context.Background()); err == nil {
		t.Fatal("immutable version reused")
	}
}

func TestPublisherPreservesUTF8BOM(t *testing.T) {
	_, _, key, _ := setup(t)
	repo := Repository{Root: t.TempDir()}
	input := []byte("\xef\xbb\xbf<?xml version=\"1.0\" encoding=\"utf-8\"?><vulnerabilities/>")
	manifest, err := repo.Publish(context.Background(), bytes.NewReader(input), "bom.1", "offline-test", key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(repo.packagePath(manifest.Snapshot.SHA256))
	if err != nil || !bytes.Equal(raw, input) {
		t.Fatal("source bytes changed", err)
	}
}
