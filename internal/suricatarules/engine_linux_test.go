// SPDX-License-Identifier: Apache-2.0
package suricatarules

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Explicitly opt-in inside an isolated network namespace with no external NIC.
func TestSuricata8NativeClassificationReload(t *testing.T) {
	if os.Getenv("CERBER_SURICATA8_SMOKE") != "1" {
		t.Skip("isolated Suricata 8 runtime required")
	}
	d := t.TempDir()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	c := Config{Directory: d, Binary: "/usr/bin/suricata", YAML: filepath.Join(d, "suricata.yaml"), Socket: filepath.Join(d, "suricata.socket"), PublicKey: base64.StdEncoding.EncodeToString(pub)}
	// Minimal independent config, no SMTP, SIEM, external traffic, or rule download.
	yaml := fmt.Sprintf("%%YAML 1.1\n---\nrunmode: single\ndefault-log-dir: %s\nclassification-file: %s\nrule-files:\n - %s\nunix-command:\n enabled: yes\n filename: %s\naf-packet:\n - interface: lo\n   threads: 1\noutputs: []\nlogging:\n default-log-level: error\n outputs:\n  - console:\n      enabled: yes\n", d, filepath.Join(d, "active.rules.classification.config"), filepath.Join(d, "active.rules"), c.Socket)
	os.WriteFile(c.YAML, []byte(yaml), 0600)
	atomic(filepath.Join(d, "active.rules"), []byte(rule2+"\n"))
	atomic(filepath.Join(d, "active.rules.classification.config"), []byte(testClass))
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Binary, "-c", c.YAML, "--af-packet=lo", "--init-errors-fatal")
	log, err := os.Create(filepath.Join(d, "engine.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = log
	cmd.Stderr = log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); cmd.Wait(); log.Close() }()
	native := NativeEngine{Config: c}
	for n := 0; n < 100; n++ {
		if _, err = native.socket(ctx, "version", nil); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		b, _ := os.ReadFile(log.Name())
		t.Fatal(err, string(b))
	}
	a, err := PackFiles("first", "feed", 8, []byte(`alert icmp any any -> any any (msg:"first"; classtype:cerber-test; sid:1; rev:1;)`), testClass)
	if err != nil {
		t.Fatal(err)
	}
	b, err := PackFiles("second", "feed", 8, []byte(`alert icmp any any -> any any (msg:"second"; classtype:cerber-new; sid:2; rev:1;)`), "config classification: cerber-new,New class,1\n")
	if err != nil {
		t.Fatal(err)
	}
	a.Manifest.Sign(key)
	b.Manifest.Sign(key)
	m := NewManager(c, native, func(_ context.Context, v Manifest) ([]byte, error) {
		if v.ID == a.Manifest.ID {
			return a.Data, nil
		}
		return b.Data, nil
	})
	if err = m.initialize(ctx); err != nil {
		t.Fatal(err)
	}
	for n, p := range []Bundle{a, b, a} {
		m.apply(ctx, assign(p, int64(n+1)))
		if v := m.Snapshot(); v.State != "applied" || v.AppliedID != p.Manifest.ID {
			t.Fatal(v)
		}
	}
}
