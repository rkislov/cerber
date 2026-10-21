// SPDX-License-Identifier: Apache-2.0
package integrations

import (
	"archive/zip"
	"bytes"
	"github.com/rkislov/cerber/internal/telemetry"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixtureZIP(t *testing.T, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	f, e := z.Create("full.csv")
	if e != nil {
		t.Fatal(e)
	}
	f.Write([]byte(body))
	z.Close()
	return b.Bytes()
}
func TestFullExportParsesOldIndicatorsAndHashes(t *testing.T) {
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	b := fixtureZIP(t, `# ThreatFox export
# "first_seen_utc","ioc_id","ioc_value","ioc_type","last_seen_utc","confidence_level","malware_printable"
"2026-07-01 00:00:00","1","192.0.2.20:443","ip:port","2026-10-01 00:00:00","90","fixture"
"2026-07-01 00:00:00","2","abcd","md5_hash","","80","fixture"
`)
	items, e := parseExport(b, now)
	if e != nil || len(items) != 2 {
		t.Fatal(items, e)
	}
	if _, e = parseExport(fixtureZIP(t, "# broken export\n"), now); e == nil {
		t.Fatal("incomplete accepted")
	}
}
func TestIOCExactIPPortAndFallbackAreDistinct(t *testing.T) {
	now := time.Now().UTC()
	x := NewIndex([]IOC{{ID: "1", Type: "ip:port", Value: "192.0.2.20:443", First: now.Add(-time.Hour), Last: now}})
	n := telemetry.Normalized{ID: "event", Status: "parsed", EventTime: now, DestinationIP: "192.0.2.20", DestinationPort: 443}
	d := x.Match(n)
	if len(d) != 1 || d[0].Rule != "threatfox.ioc_match" {
		t.Fatal(d)
	}
	n.DestinationPort = 80
	d = x.Match(n)
	if len(d) != 1 || d[0].Rule != "threatfox.ip_match" || d[0].Severity != "medium" {
		t.Fatal(d)
	}
	n.DestinationIP = "192.0.2.21"
	if len(x.Match(n)) != 0 {
		t.Fatal("unrelated IP matched")
	}
	n.DestinationIP = "192.0.2.20"
	n.EventTime = now.Add(-24 * time.Hour)
	if len(x.Match(n)) != 0 {
		t.Fatal("pre-IOC event matched")
	}
}
func TestSMTPAndThreatFoxSaveScopesPreserveOtherSection(t *testing.T) {
	s := testStore(t)
	key := "fixture"
	enabled := true
	if e := s.Save(Command{Version: 1, Scope: "threatfox", ThreatFoxKey: &key, ThreatFoxEnabled: &enabled}, "roman"); e != nil {
		t.Fatal(e)
	}
	if e := s.Save(Command{Version: 2, Scope: "smtp", SMTP: SMTP{Host: "mail.example.org", Port: 587, Security: "starttls"}}, "roman"); e != nil {
		t.Fatal(e)
	}
	if s.snapshot().ThreatFoxKey != key || !s.View().ThreatFoxEnabled {
		t.Fatal("SMTP erased ThreatFox")
	}
	if e := s.Save(Command{Version: 3, Scope: "threatfox", ThreatFoxEnabled: &enabled}, "roman"); e != nil || s.View().SMTP.Host != "mail.example.org" {
		t.Fatal("ThreatFox erased SMTP", e)
	}
}

func testStore(t *testing.T) *Store {
	t.Helper()
	d := t.TempDir()
	key := filepath.Join(d, "key")
	os.WriteFile(key, bytes.Repeat([]byte{3}, 32), 0600)
	s, e := Open(filepath.Join(d, "settings"), key)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
