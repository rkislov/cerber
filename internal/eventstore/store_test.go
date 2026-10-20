// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/telemetry"
	"path/filepath"
	"testing"
	"time"
)

func batch(t *testing.T, agent string, start int, outcomes ...string) telemetry.Batch {
	t.Helper()
	now := time.Now().UTC().Add(-time.Minute)
	b := telemetry.Batch{SchemaVersion: 1, ID: telemetry.ID(agent, "batch", string(rune(start))), AgentID: agent}
	for i, outcome := range outcomes {
		code := 4625
		if outcome == "success" {
			code = 4624
		}
		if outcome == "audit" {
			code = 1102
		}
		p, _ := json.Marshal(map[string]any{"event_id": code, "time": now.Add(time.Duration(start+i) * time.Second).Format(time.RFC3339Nano), "provider": "Microsoft-Windows-Security-Auditing", "fields": map[string]string{"TargetUserName": "Alice", "TargetDomainName": "LAB", "IpAddress": "10.1.2.3"}})
		c := telemetry.ID(agent, string(rune(start+i)))
		b.Records = append(b.Records, telemetry.Raw{ID: telemetry.ID("record", c), Source: "windows:Security", Cursor: c, ObservedAt: now, Data: p})
	}
	return b
}
func TestDurableReplayCorrelationAndOwnership(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "events.db")
	s, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	agent := telemetry.ID("agent")
	b := batch(t, agent, 0, "failure", "failure", "failure", "failure", "failure", "failure", "success", "audit")
	r, e := s.Accept(ctx, agent, "server-bound-asset", b)
	if e != nil {
		t.Fatal(e)
	}
	duplicate, e := s.Accept(ctx, agent, "ignored-on-retry", b)
	if e != nil || !duplicate.ReceivedAt.Equal(r.ReceivedAt) {
		t.Fatalf("duplicate receipt: %+v %v", duplicate, e)
	}
	b.Records[0].Cursor = "changed"
	if _, e = s.Accept(ctx, agent, "asset", b); !errors.Is(e, telemetry.ErrConflict) {
		t.Fatalf("immutable batch: %v", e)
	}
	s.Close()
	s, e = Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.Step(ctx); e != nil {
		t.Fatal(e)
	}
	if e = s.Step(ctx); e != nil {
		t.Fatal(e)
	}
	items, e := s.ReadEvents(ctx, telemetry.Query{Limit: 100})
	if e != nil || len(items) != 8 {
		t.Fatalf("events %d %v", len(items), e)
	}
	for _, n := range items {
		if n.AssetID != "server-bound-asset" {
			t.Fatal("asset ownership")
		}
		if _, e = s.ReadRaw(ctx, n.ID); e != nil {
			t.Fatal(e)
		}
	}
	d, e := s.ReadDetections(ctx, 0, 100)
	if e != nil || len(d) != 3 {
		t.Fatalf("detections %+v %v", d, e)
	}
	for _, v := range d {
		if v.Rule == "auth.success_after_failures" && len(v.Evidence) != 7 {
			t.Fatalf("evidence %+v", v)
		}
		if e = s.Acknowledge(ctx, v.ID, "operator"); e != nil {
			t.Fatal(e)
		}
	}
	d, _ = s.ReadDetections(ctx, 0, 100)
	if d[0].State != "acknowledged" || d[0].AcknowledgedBy != "operator" {
		t.Fatal(d)
	}
	other := batch(t, telemetry.ID("other"), 0, "failure")
	if _, e = s.Accept(ctx, agent, "asset", other); !errors.Is(e, telemetry.ErrInvalid) {
		t.Fatal(e)
	}
	status, e := s.Status(ctx)
	if e != nil || status.Raw != 8 || status.Normalized != 8 || status.ProcessorCursor != 8 || status.CorrelatorCursor != 8 {
		t.Fatalf("status %+v %v", status, e)
	}
}
func TestSpoolCursorAtomicityAndBackpressure(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, filepath.Join(t.TempDir(), "spool.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	a := telemetry.ID("agent")
	b := batch(t, a, 1, "failure")
	next := b.Records[0].Cursor
	if e = s.Enqueue(ctx, b, "windows:Security", "", next); e != nil {
		t.Fatal(e)
	}
	if c, _ := s.SourceCursor(ctx, a, "windows:Security"); c != next {
		t.Fatal(c)
	}
	if e = s.Enqueue(ctx, b, "windows:Security", "", next); !errors.Is(e, telemetry.ErrConflict) {
		t.Fatal(e)
	}
	stored, e := s.NextBatch(ctx, a)
	if e != nil || stored.ID != b.ID {
		t.Fatal(e)
	}
	if e = s.Ack(ctx, b, telemetry.Receipt{BatchID: b.ID, AgentID: a, Count: 2, ReceivedAt: time.Now()}); !errors.Is(e, telemetry.ErrInvalid) {
		t.Fatal("bad ack removed batch")
	}
	if _, e = s.NextBatch(ctx, a); e != nil {
		t.Fatal(e)
	}
	if e = s.Ack(ctx, b, telemetry.Receipt{BatchID: b.ID, AgentID: a, Count: 1, ReceivedAt: time.Now()}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.NextBatch(ctx, a); !errors.Is(e, telemetry.ErrNotFound) {
		t.Fatal(e)
	}
	// Audit the failure boundary: enqueue trigger failure must roll back source cursor.
	_, e = s.db.ExecContext(ctx, `CREATE TRIGGER fail_spool BEFORE INSERT ON event_spool BEGIN SELECT RAISE(ABORT,'disk failure'); END`)
	if e != nil {
		t.Fatal(e)
	}
	second := batch(t, a, 2, "failure")
	if e = s.Enqueue(ctx, second, "windows:Security", next, second.Records[0].Cursor); e == nil {
		t.Fatal("expected failure")
	}
	if c, _ := s.SourceCursor(ctx, a, "windows:Security"); c != next {
		t.Fatal("lost cursor")
	}
}
func TestQuarantineAndConsumerRollback(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	a := telemetry.ID("a")
	b := batch(t, a, 0, "failure")
	b.Records[0].Data = json.RawMessage(`{"event_id":"invalid"}`)
	if _, e = s.Accept(ctx, a, "asset", b); e != nil {
		t.Fatal(e)
	}
	_, e = s.db.ExecContext(ctx, `CREATE TRIGGER fail_normalize BEFORE INSERT ON normalized_events BEGIN SELECT RAISE(ABORT,'failure'); END`)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Step(ctx); e == nil {
		t.Fatal("expected pipeline failure")
	}
	v, _ := s.Status(ctx)
	if v.ProcessorCursor != 0 || v.Normalized != 0 {
		t.Fatal(v)
	}
	s.db.ExecContext(ctx, "DROP TRIGGER fail_normalize")
	if e = s.Step(ctx); e != nil {
		t.Fatal(e)
	}
	items, e := s.ReadEvents(ctx, telemetry.Query{Status: "quarantine", Limit: 100})
	if e != nil || len(items) != 1 || items[0].Status != "quarantine" {
		t.Fatal(items, e)
	}
	ds, _ := s.ReadDetections(ctx, 0, 100)
	if len(ds) != 0 {
		t.Fatal(ds)
	}
}
func TestCorrelationWindowAndAgentIsolation(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	a := telemetry.ID("a")
	b := batch(t, a, 0, "failure", "failure", "failure", "failure")
	if _, e = s.Accept(ctx, a, "asset", b); e != nil {
		t.Fatal(e)
	}
	other := batch(t, telemetry.ID("b"), 0, "failure")
	if _, e = s.Accept(ctx, other.AgentID, "asset-b", other); e != nil {
		t.Fatal(e)
	}
	if e = s.Step(ctx); e != nil {
		t.Fatal(e)
	}
	ds, _ := s.ReadDetections(ctx, 0, 100)
	if len(ds) != 0 {
		t.Fatal("cross-agent correlation")
	}
	late := batch(t, a, 500, "failure")
	var v map[string]any
	json.Unmarshal(late.Records[0].Data, &v)
	v["time"] = time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339Nano)
	late.Records[0].Data, _ = json.Marshal(v)
	if _, e = s.Accept(ctx, a, "asset", late); e != nil {
		t.Fatal(e)
	}
	if e = s.Step(ctx); e != nil {
		t.Fatal(e)
	}
	ds, _ = s.ReadDetections(ctx, 0, 100)
	if len(ds) != 0 {
		t.Fatal("out-of-window correlation")
	}
}
func TestJournalQuotaRollsBackWholeBatch(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.db.ExecContext(ctx, "UPDATE journal_usage SET raw_bytes=?", 1<<30); e != nil {
		t.Fatal(e)
	}
	a := telemetry.ID("agent")
	if _, e = s.Accept(ctx, a, "asset", batch(t, a, 0, "failure")); !errors.Is(e, telemetry.ErrFull) {
		t.Fatal(e)
	}
	v, _ := s.Status(ctx)
	if v.Raw != 0 {
		t.Fatal("partially committed full journal", v)
	}
}
