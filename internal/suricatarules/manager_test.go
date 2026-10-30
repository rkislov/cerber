// SPDX-License-Identifier: Apache-2.0
package suricatarules

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const rule1 = `alert icmp any any -> any any (msg:"a; sid:123;"; sid:1000001; rev:1;)`
const rule2 = `alert tcp any any -> any any (msg:"b"; sid:1000002; rev:1;)`

func TestPackageValidationAndTamper(t *testing.T) {
	for _, s := range []string{"", rule1 + "\n" + rule1, `alert tcp any any -> any any (sid:1; rev:0;)`, `alert tcp any any -> any any (sid:1; rev:1; lua:"/tmp/x";)`, `alert tcp any any -> any any (msg:"sid:1; rev:1;";)`} {
		if _, _, e := Normalize([]byte(s)); e == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	b, e := Pack("own", "custom", 7, []byte("# comment\n"+rule1))
	if e != nil {
		t.Fatal(e)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	b.Manifest.Sign(key)
	k := base64.StdEncoding.EncodeToString(pub)
	if e = b.Manifest.Verify(k); e != nil {
		t.Fatal(e)
	}
	if _, e = Unpack(b.Manifest, b.Data); e != nil {
		t.Fatal(e)
	}
	altered := b.Manifest
	altered.EngineMajor = 8
	if altered.Verify(k) == nil {
		t.Fatal("unsigned engine change accepted")
	}
	b.Data[0] ^= 1
	if _, e = Unpack(b.Manifest, b.Data); e == nil {
		t.Fatal("checksum not checked")
	}
}
func TestPCREInnerQuotesAndSIDOverflow(t *testing.T) {
	rule := `alert http any any -> any any (pcre:"/^["']?post/Ri"; sid:123; rev:2;)`
	if _, _, e := Normalize([]byte(rule)); e != nil {
		t.Fatal(e)
	}
	if _, _, e := Normalize([]byte(`alert tcp any any -> any any (sid:4294967296; rev:1;)`)); e == nil {
		t.Fatal("overflow accepted")
	}
}
func TestETArchiveLimitsAndPaths(t *testing.T) {
	archive := func(name string, typ byte) []byte {
		var b bytes.Buffer
		z := gzip.NewWriter(&b)
		w := tar.NewWriter(z)
		h := tar.Header{Name: name, Typeflag: typ, Mode: 0600}
		if typ == tar.TypeReg {
			h.Size = int64(len(rule1))
		}
		_ = w.WriteHeader(&h)
		if typ == tar.TypeReg {
			_, _ = w.Write([]byte(rule1))
		}
		_ = w.Close()
		_ = z.Close()
		return b.Bytes()
	}
	for _, name := range []string{"../bad.rules", "/absolute.rules", "a/../bad.rules"} {
		if _, e := ExtractET(archive(name, tar.TypeReg)); e == nil {
			t.Fatal(name)
		}
	}
	if _, e := ExtractET(archive("rules/x.rules", tar.TypeSymlink)); e == nil {
		t.Fatal("symlink accepted")
	}
	bad := archive("rules/x.rules", tar.TypeReg)
	bad[len(bad)-8] ^= 1
	if _, e := ExtractET(bad); e == nil {
		t.Fatal("gzip checksum ignored")
	}
	if _, e := ExtractET(archive("rules/x.rules", tar.TypeReg)); e != nil {
		t.Fatal(e)
	}
}

type fakeEngine struct {
	badTest   bool
	badReload int
	reloaded  []int
}

func (e *fakeEngine) Major(context.Context) (int, error) { return 7, nil }
func (e *fakeEngine) Test(context.Context, string) error {
	if e.badTest {
		return errors.New("invalid syntax")
	}
	return nil
}
func (e *fakeEngine) Reload(_ context.Context, n int) error {
	e.reloaded = append(e.reloaded, n)
	if e.badReload > 0 {
		e.badReload--
		return errors.New("reload failed")
	}
	return nil
}
func fixture(t *testing.T) (*Manager, *fakeEngine, Bundle, Bundle) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	a, _ := Pack("a", "custom", 7, []byte(rule1))
	b, _ := Pack("b", "custom", 7, []byte(rule2))
	a.Manifest.Sign(key)
	b.Manifest.Sign(key)
	dir := t.TempDir()
	c := Config{Directory: dir, Binary: filepath.Join(dir, "suricata"), YAML: filepath.Join(dir, "suricata.yaml"), Socket: filepath.Join(dir, "socket"), PublicKey: base64.StdEncoding.EncodeToString(pub)}
	engine := &fakeEngine{}
	m := NewManager(c, engine, func(_ context.Context, v Manifest) ([]byte, error) {
		if v.ID == a.Manifest.ID {
			return a.Data, nil
		}
		return b.Data, nil
	})
	if e := m.initialize(context.Background()); e != nil {
		t.Fatal(e)
	}
	return m, engine, a, b
}
func assign(b Bundle, revision int64) Assignment {
	return Assignment{Revision: revision, Bundle: b.Manifest, UpdatedAt: time.Now().UTC()}
}
func TestActivationRejectsInvalidRulesAndRestoresFailedReload(t *testing.T) {
	ctx := context.Background()
	m, e, a, b := fixture(t)
	m.apply(ctx, assign(a, 1))
	if s := m.Snapshot(); s.State != "applied" || s.AppliedID != a.Manifest.ID {
		t.Fatal(s)
	}
	original, _ := os.ReadFile(m.file("active.rules"))
	e.badTest = true
	m.apply(ctx, assign(b, 2))
	current, _ := os.ReadFile(m.file("active.rules"))
	if !bytes.Equal(original, current) || m.Snapshot().AppliedID != a.Manifest.ID {
		t.Fatal("invalid candidate replaced rules")
	}
	e.badTest = false
	e.badReload = 1
	m.apply(ctx, assign(b, 3))
	current, _ = os.ReadFile(m.file("active.rules"))
	if !bytes.Equal(original, current) || m.Snapshot().State != "error" {
		t.Fatal(m.Snapshot())
	}
	if _, err := os.Stat(m.file("transaction.json")); !os.IsNotExist(err) {
		t.Fatal("journal not cleared")
	}
	m.apply(ctx, assign(b, 4))
	if m.Snapshot().AppliedID != b.Manifest.ID {
		t.Fatal(m.Snapshot())
	}
	m.apply(ctx, assign(a, 5))
	if m.Snapshot().AppliedID != a.Manifest.ID {
		t.Fatal("rollback assignment failed")
	}
	restarted := NewManager(m.config, e, m.download)
	if err := restarted.initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if restarted.Snapshot().Revision != 5 {
		t.Fatal("lost state")
	}
}
func TestInterruptedActivationRecoversAndFailedRollbackBlocksNext(t *testing.T) {
	ctx := context.Background()
	m, e, a, b := fixture(t)
	m.apply(ctx, assign(a, 1))
	before := m.current()
	original, _ := os.ReadFile(m.file("active.rules"))
	_ = atomic(m.file("previous.rules"), original)
	candidate, _, _ := Normalize([]byte(rule2))
	_ = atomic(m.file("active.rules"), candidate)
	attempt := before
	attempt.Status.Revision = 2
	attempt.Status.DesiredID = b.Manifest.ID
	data, _ := json.Marshal(transaction{Before: before, Attempt: attempt})
	_ = atomic(m.file("transaction.json"), data)
	restart := NewManager(m.config, e, m.download)
	if err := restart.initialize(ctx); err != nil {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(m.file("active.rules"))
	if !bytes.Equal(current, original) || restart.Snapshot().Revision != 2 || restart.Snapshot().AppliedID != a.Manifest.ID {
		t.Fatal(restart.Snapshot())
	}
	e.badReload = 2
	restart.apply(ctx, assign(b, 3))
	if restart.Snapshot().State != "rollback_failed" {
		t.Fatal(restart.Snapshot())
	}
	calls := len(e.reloaded)
	restart.apply(ctx, assign(b, 4))
	if len(e.reloaded) != calls {
		t.Fatal("overwrote unresolved recovery transaction")
	}
}
func TestCorruptDownloadPreservesApplied(t *testing.T) {
	m, _, a, b := fixture(t)
	m.apply(context.Background(), assign(a, 1))
	m.download = func(context.Context, Manifest) ([]byte, error) { return []byte("corrupt"), nil }
	m.apply(context.Background(), assign(b, 2))
	if m.Snapshot().AppliedID != a.Manifest.ID || m.Snapshot().State != "error" {
		t.Fatal(m.Snapshot())
	}
}
