// SPDX-License-Identifier: Apache-2.0
package suricatarules

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const testClass = "config classification: cerber-test,Cerber test, 2\n"

func feedFixture(t *testing.T) (FeedCatalog, map[string][]byte) {
	t.Helper()
	c := FeedCatalog{Format: "security-feed-suricata-catalog-v1"}
	archives := map[string][]byte{}
	for n, id := range feedSources {
		var b bytes.Buffer
		z := gzip.NewWriter(&b)
		w := tar.NewWriter(z)
		files := map[string]string{"rules/fixture.rules": fmt.Sprintf("alert icmp any any -> any any (sid:%d; rev:1;)\n", n+1)}
		if id == "et-open" {
			files["rules/classification.config"] = testClass
		}
		for name, s := range files {
			w.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(s))})
			w.Write([]byte(s))
		}
		w.Close()
		z.Close()
		raw := b.Bytes()
		archives[id] = raw
		c.Sources = append(c.Sources, FeedItem{ID: id, DownloadPath: "/feeds/v1/suricata/" + id + ".tar.gz", SHA256: Hash(raw), Size: len(raw), RuleCount: 1})
	}
	return c, archives
}
func TestFeedDownloadAuthenticatesEveryRequestAndVerifiesArchives(t *testing.T) {
	c, archives := feedFixture(t)
	badHash, redirect := false, false
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("User-Agent") != "Cerber-SIEM/1" || r.Header.Get("X-Api-Key") != "fixture-key" || r.URL.RawQuery != "" {
			t.Error("unsafe authorization")
		}
		switch r.URL.Path {
		case "/feeds/v1/catalog.json":
			if redirect {
				http.Redirect(w, r, "https://other.invalid", 302)
				return
			}
			fmt.Fprint(w, `{"project":"cerber","suricata_rules":"/feeds/v1/suricata/catalog.json"}`)
		case feedCatalogPath:
			json.NewEncoder(w).Encode(c)
		default:
			for id, b := range archives {
				if r.URL.Path == "/feeds/v1/suricata/"+id+".tar.gz" {
					if badHash {
						b = append([]byte{}, b...)
						b[len(b)-1] ^= 1
					}
					w.Write(b)
					return
				}
			}
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := NewFeedClient()
	client.origin = srv.URL
	b, e := client.Download(context.Background(), "fixture-key", 8)
	if e != nil || b.Manifest.Count != 5 || calls != 7 {
		t.Fatal(b.Manifest, calls, e)
	}
	_, classes, e := UnpackFiles(b.Manifest, b.Data)
	if e != nil || classes != testClass {
		t.Fatal(classes, e)
	}
	badHash = true
	if _, e = client.Download(context.Background(), "fixture-key", 8); e == nil || strings.Contains(e.Error(), "fixture-key") {
		t.Fatal("hash/redaction", e)
	}
	redirect = true
	if _, e = client.Catalog(context.Background(), "fixture-key"); e == nil {
		t.Fatal("redirect followed")
	}
	calls = 0
	if _, e = client.Download(context.Background(), "fixture-key", 7); e == nil || calls != 0 {
		t.Fatal("old engine accepted")
	}
}
func TestFeedCatalogRejectsExternalPathsAndIncompleteSets(t *testing.T) {
	c, _ := feedFixture(t)
	for _, path := range []string{"https://other.invalid/key", "//other.invalid/key", "/feeds/v1/suricata/../key", "/feeds/v1/suricata/et-open.tar.gz?key=x"} {
		c.Sources[0].DownloadPath = path
		b, _ := json.Marshal(c)
		if _, e := parseFeedCatalog(b, false); e == nil {
			t.Fatal(path)
		}
	}
}
func TestFeedOfflineZIPUsesSameVerifiedBundles(t *testing.T) {
	c, archives := feedFixture(t)
	want, e := assembleFeed(c, func(i FeedItem) ([]byte, error) { return archives[i.ID], nil })
	if e != nil {
		t.Fatal(e)
	}
	var raw bytes.Buffer
	z := zip.NewWriter(&raw)
	entries := map[string][]byte{}
	for i := range c.Sources {
		c.Sources[i].DownloadPath = c.Sources[i].ID + ".tar.gz"
		entries["suricata/"+c.Sources[i].DownloadPath] = archives[c.Sources[i].ID]
	}
	entries["suricata/catalog.json"], _ = json.Marshal(c)
	files := map[string]any{}
	for name, b := range entries {
		files[name] = map[string]any{"sha256": Hash(b), "bytes": len(b)}
	}
	entries["manifest.json"], _ = json.Marshal(map[string]any{"format": "security-feed-project-v1", "project": "cerber", "files": files})
	for name, b := range entries {
		w, _ := z.Create(name)
		w.Write(b)
	}
	z.Close()
	got, e := ImportFeedZIP(bytes.NewReader(raw.Bytes()), int64(raw.Len()))
	if e != nil || got.Manifest.ID != want.Manifest.ID {
		t.Fatal(e, got.Manifest, want.Manifest)
	}
}
func TestClassificationRollbackAndRecovery(t *testing.T) {
	m, engine, _, _ := fixture(t)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	m.config.PublicKey = base64.StdEncoding.EncodeToString(pub)
	a, e := PackFiles("a", "feed", 7, []byte(rule1), testClass)
	if e != nil {
		t.Fatal(e)
	}
	b, e := PackFiles("b", "feed", 7, []byte(rule2), strings.ReplaceAll(testClass, " 2", " 1"))
	if e != nil {
		t.Fatal(e)
	}
	a.Manifest.Sign(key)
	b.Manifest.Sign(key)
	m.download = func(_ context.Context, v Manifest) ([]byte, error) {
		if v.ID == a.Manifest.ID {
			return a.Data, nil
		}
		return b.Data, nil
	}
	m.apply(context.Background(), assign(a, 1))
	if m.Snapshot().State != "applied" {
		t.Fatal(m.Snapshot())
	}
	engine.badReload = 1
	m.apply(context.Background(), assign(b, 2))
	classes, _ := os.ReadFile(m.file("active.rules.classification.config"))
	if string(classes) != testClass || m.Snapshot().AppliedID != a.Manifest.ID {
		t.Fatal("classification was not restored", m.Snapshot())
	}
	before := m.current()
	old, _ := os.ReadFile(m.file("active.rules"))
	atomic(m.file("previous.rules"), old)
	atomic(m.file("previous.rules.classification.config"), classes)
	atomic(m.file("active.rules.classification.config"), []byte("config classification: other,Other,1\n"))
	journal, _ := json.Marshal(transaction{Before: before, Attempt: before, ClassificationChanged: true, HadClassification: true})
	atomic(m.file("transaction.json"), journal)
	restarted := NewManager(m.config, engine, m.download)
	if e = restarted.initialize(context.Background()); e != nil {
		t.Fatal(e)
	}
	classes, _ = os.ReadFile(m.file("active.rules.classification.config"))
	if string(classes) != testClass {
		t.Fatal("interrupted classification swap not restored")
	}
}
func TestClassificationAndOptionalRev(t *testing.T) {
	if _, _, e := Normalize([]byte(`alert icmp any any -> any any (sid:1;)`)); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"include: /tmp/file", testClass + testClass, "config classification: x,Bad,0"} {
		if ValidateClassification(s) == nil {
			t.Fatal(s)
		}
	}
	a, _ := PackFiles("a", "feed", 8, []byte(rule1), testClass)
	b, _ := PackFiles("a", "feed", 8, []byte(rule1), strings.ReplaceAll(testClass, " 2", " 1"))
	if a.Manifest.ID == b.Manifest.ID {
		t.Fatal("classification omitted from bundle identity")
	}
}
