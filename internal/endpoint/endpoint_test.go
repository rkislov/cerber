// SPDX-License-Identifier: Apache-2.0
package endpoint

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/integrations"
	"github.com/rkislov/cerber/internal/telemetry"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Server, ed25519.PublicKey) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	s, e := Open(filepath.Join(t.TempDir(), "endpoint.db"), key, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, pub
}
func testPolicy(mode string) Policy {
	return Policy{Name: "Servers", Class: "server", Mode: mode, ScanIntervalMinutes: 1440, ScanHourUTC: 0, SyncMinutes: 60, Agents: []string{"agent"}, Exclude: []string{}, Protected: []string{"203.0.113.1"}}
}
func TestLearningNeverDeliversBlocksAndConfirmExpires(t *testing.T) {
	ctx := context.Background()
	s, pub := fixture(t)
	p := testPolicy("learning")
	if e := s.Command(ctx, Command{Action: "policy", Policy: p, Confirm: true}, "roman", nil); e != nil {
		t.Fatal(e)
	}
	if e := s.Observe(ctx, []telemetry.Detection{{ID: "detection", AgentID: "agent", Rule: "threatfox.ip_match", SourceIP: "198.51.100.10"}}); e != nil {
		t.Fatal(e)
	}
	signed, e := s.Exchange(ctx, "agent", "asset", Report{})
	if e != nil {
		t.Fatal(e)
	}
	b, e := signed.Verify(pub, "agent", time.Now())
	if e != nil || len(b.Blocks) != 0 {
		t.Fatal(b, e)
	}
	v, _ := s.View(ctx)
	policies := v["policies"].([]json.RawMessage)
	json.Unmarshal(policies[0], &p)
	p.Mode = "confirm"
	if e = s.Command(ctx, Command{Action: "policy", Policy: p, Confirm: true}, "roman", nil); e != nil {
		t.Fatal(e)
	}
	c := Command{Action: "block", Agent: "agent", IP: "198.51.100.10", Minutes: 1, Reason: "controlled test", Confirm: true}
	if e = s.Command(ctx, c, "roman", nil); e != nil {
		t.Fatal(e)
	}
	signed, e = s.Exchange(ctx, "agent", "asset", Report{})
	if e != nil {
		t.Fatal(e)
	}
	b, e = signed.Verify(pub, "agent", time.Now())
	if e != nil || len(b.Blocks) != 1 {
		t.Fatal(b, e)
	}
	if e = s.Command(ctx, Command{Action: "cancel", ID: b.Blocks[0].ID}, "roman", nil); e != nil {
		t.Fatal(e)
	}
	signed, _ = s.Exchange(ctx, "agent", "asset", Report{})
	b, _ = signed.Verify(pub, "agent", time.Now())
	if len(b.Blocks) != 0 {
		t.Fatal("cancel not removed")
	}
	if _, e = signed.Verify(pub, "other", time.Now()); e == nil {
		t.Fatal("wrong agent signature accepted")
	}
	signed.Payload[0] ^= 1
	if _, e = signed.Verify(pub, "agent", time.Now()); e == nil {
		t.Fatal("tamper accepted")
	}
}
func TestProtectedIPAndConfirmation(t *testing.T) {
	s, _ := fixture(t)
	ctx := context.Background()
	p := testPolicy("confirm")
	if e := s.Command(ctx, Command{Action: "policy", Policy: p, Confirm: true}, "roman", nil); e != nil {
		t.Fatal(e)
	}
	for _, ip := range []string{"2001:db8::1%unsafe-zone", "203.0.113.1", "127.0.0.1", "10.1.2.3", "85.137.24.140"} {
		c := Command{Action: "block", Agent: "agent", IP: ip, Minutes: 30, Confirm: true, Reason: "controlled test"}
		if e := s.Command(ctx, c, "roman", []string{"85.137.24.140", "10.1.2.3"}); e == nil {
			t.Fatal("protected accepted", ip)
		}
	}
	if e := s.Command(ctx, Command{Action: "block", Agent: "agent", IP: "198.51.100.10", Minutes: 1, Reason: "not confirmed"}, "roman", nil); e == nil {
		t.Fatal("no confirmation accepted")
	}
}
func TestFileIOCScanReadOnlyAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.txt")
	data := []byte("harmless IOC fixture")
	os.WriteFile(path, data, 0600)
	os.Symlink(path, filepath.Join(dir, "link.txt"))
	h := sha256.Sum256(data)
	ioc := integrations.IOC{ID: "fixture", Type: "sha256_hash", Value: hex.EncodeToString(h[:])}
	r := scanRootsForTest(context.Background(), dir, []integrations.IOC{ioc})
	if len(r.Findings) != 1 || r.Findings[0].Path != path || r.Scanned != 1 {
		t.Fatal(r)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(data) {
		t.Fatal("file modified")
	}
}

func scanRootsForTest(ctx context.Context, root string, iocs []integrations.IOC) scanResult {
	return scanWithRoots(ctx, testPolicy("off"), iocs, "", []string{root}, nil)
}

type fakeExchange struct {
	reply  Signed
	report Report
	fail   bool
}

func (f *fakeExchange) EndpointExchange(_ context.Context, r Report) (Signed, error) {
	f.report = r
	if f.fail {
		return Signed{}, ErrInvalid
	}
	return f.reply, nil
}
func TestOfflineCancellationAcknowledgmentSurvivesUntilExchange(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	p := testPolicy("confirm")
	p.ID = "test"
	p.Version = 1
	b := Bundle{Agent: "agent", Issued: now, Expires: now.Add(time.Hour), Policy: p, Blocks: []Block{}}
	signed, _ := Sign(b, key)
	old := Block{ID: strings.Repeat("a", 32), Agent: "agent", IP: "198.51.100.10", Expires: now.Add(5 * time.Minute)}
	removed := false
	l := &Local{path: filepath.Join(t.TempDir(), "state.json"), key: pub, agent: "agent", apply: func(_ context.Context, _ Block, add bool) error {
		if !add {
			removed = true
		}
		return nil
	}, state: localState{Signed: signed, Blocks: []Block{old}, NextSync: now.Add(time.Hour)}}
	client := &fakeExchange{reply: signed, fail: true}
	if e := l.Step(context.Background(), client); e != nil || !removed || l.state.Report.Blocks[old.ID] != "removed" {
		t.Fatal("offline rollback not retained", e, l.state.Report)
	}
	l.state.NextSync = time.Time{}
	if e := l.Step(context.Background(), client); e == nil || l.state.Report.Blocks[old.ID] != "removed" {
		t.Fatal("failed transport lost acknowledgment")
	}
	client.fail = false
	if e := l.Step(context.Background(), client); e != nil || client.report.Blocks[old.ID] != "removed" {
		t.Fatal("rollback not reported", e, client.report)
	}
}

func TestCacheCleanupKeepsOnlyCommittedVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	current, old := strings.Repeat("a", 64), strings.Repeat("b", 64)
	os.WriteFile(path+".ioc."+current, []byte("current"), 0600)
	os.WriteFile(path+".ioc."+old, []byte("old"), 0600)
	os.WriteFile(path+".ioc.notes", []byte("unrelated"), 0600)
	l := &Local{path: path, state: localState{FeedVersion: current}}
	if e := l.save(); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(path + ".ioc." + old); !os.IsNotExist(e) {
		t.Fatal("obsolete cache retained")
	}
	if _, e := os.Stat(path + ".ioc." + current); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(path + ".ioc.notes"); e != nil {
		t.Fatal("unrelated file removed")
	}
}

func TestLocalCachedEventIOCMatchingIsPassiveAndExpires(t *testing.T) {
	now := time.Now().UTC()
	l := &Local{agent: "agent", seen: map[string]bool{}}
	l.eventIndex.Store(integrations.NewIndex([]integrations.IOC{{ID: "test", Type: "ip:port", Value: "192.0.2.4:443", First: now.Add(-time.Hour), Last: now}}))
	l.validUntil.Store(now.Add(time.Hour).Unix())
	data, _ := json.Marshal(map[string]any{"event_id": 4625, "time": now.Format(time.RFC3339Nano), "provider": "Microsoft-Windows-Security-Auditing", "fields": map[string]string{"IpAddress": "192.0.2.4", "TargetUserName": "fixture"}})
	raw := telemetry.Raw{ID: telemetry.ID("event-fixture"), Source: "windows:Security", ObservedAt: now, Data: data}
	l.ObserveEvents([]telemetry.Raw{raw})
	l.ObserveEvents([]telemetry.Raw{raw})
	if l.matchCount.Load() != 1 {
		t.Fatal("cache not used or cursor replay counted twice")
	}
	l.validUntil.Store(now.Add(-time.Second).Unix())
	raw.ID = telemetry.ID("second-fixture")
	l.ObserveEvents([]telemetry.Raw{raw})
	if l.matchCount.Load() != 1 {
		t.Fatal("expired policy still matched")
	}
}

type fakeBinding struct{}

func (fakeBinding) AgentBinding(context.Context, string, string) (string, error) { return "asset", nil }

type captureSink struct{ count int }

func (s *captureSink) Accept(_ context.Context, _ string, _ string, b telemetry.Batch) (telemetry.Receipt, error) {
	if e := b.Validate(); e != nil {
		return telemetry.Receipt{}, e
	}
	s.count = len(b.Records)
	return telemetry.Receipt{BatchID: b.ID}, nil
}
func TestEndpointReceivesBoundedLongPathFindingBatch(t *testing.T) {
	s, _ := fixture(t)
	sink := &captureSink{}
	s.events = sink
	r := Report{}
	for i := 0; i < 100; i++ {
		r.Findings = append(r.Findings, Finding{ID: telemetry.ID(fmt.Sprint(i)), Path: "/" + strings.Repeat("x", 4000), SHA256: strings.Repeat("a", 64), MD5: strings.Repeat("b", 32), At: time.Now().UTC()})
	}
	body, _ := json.Marshal(r)
	if len(body) <= 256<<10 {
		t.Fatal("fixture does not cover old request limit")
	}
	request := httptest.NewRequest("POST", "/v1/agent/endpoint", bytes.NewReader(body))
	request.Header.Set("X-Cerber-Agent", strings.Repeat("a", 32))
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("q", 64))
	w := httptest.NewRecorder()
	s.Handler(fakeBinding{}).ServeHTTP(w, request)
	if w.Code != 200 || sink.count != 100 {
		t.Fatal(w.Code, w.Body.String(), sink.count)
	}
	request = httptest.NewRequest("POST", "/v1/agent/endpoint", strings.NewReader("{}"))
	request.Header.Set("X-Cerber-Agent", strings.Repeat("a", 32))
	request.Header.Set("Authorization", strings.Repeat("q", 64))
	w = httptest.NewRecorder()
	s.Handler(fakeBinding{}).ServeHTTP(w, request)
	if w.Code != 401 {
		t.Fatal("non-bearer credential accepted")
	}
}

func TestReplayRejectedBeforeIOCCacheMutation(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	p := testPolicy("off")
	p.ID = "stable"
	p.Version = 2
	current := Bundle{Agent: "agent", Issued: now, Expires: now.Add(time.Hour), Policy: p}
	signed, _ := Sign(current, key)
	items := []integrations.IOC{{ID: "old", Type: "ip", Value: "192.0.2.1"}}
	old := current
	old.Issued = now.Add(-time.Minute)
	old.IOCs = items
	old.FeedVersion = snapshotID(items)
	reply, _ := Sign(old, key)
	l := &Local{path: filepath.Join(t.TempDir(), "state.json"), key: pub, agent: "agent", state: localState{Signed: signed}}
	if e := l.Step(context.Background(), &fakeExchange{reply: reply}); e == nil {
		t.Fatal("replay accepted")
	}
	if l.state.FeedVersion != "" || len(l.state.IOCs) != 0 {
		t.Fatal("cache mutated before replay rejection")
	}
	files, _ := filepath.Glob(l.path + ".ioc.*")
	if len(files) != 0 {
		t.Fatal("replayed cache was written")
	}
}
