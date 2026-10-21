// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/cerber/internal/telemetry"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func journalBatch(agent string, start, count int, at time.Time) telemetry.Batch {
	b := telemetry.Batch{SchemaVersion: 1, ID: telemetry.ID(agent, "batch", fmt.Sprint(start)), AgentID: agent}
	for i := 0; i < count; i++ {
		cursor := fmt.Sprint(start + i)
		p, _ := json.Marshal(map[string]any{"__REALTIME_TIMESTAMP": fmt.Sprint(at.UnixMicro()), "MESSAGE": "Ошибка подключения сервер один", "EXTRA": "needle-private", "_UID": "1000"})
		b.Records = append(b.Records, telemetry.Raw{ID: telemetry.ID("event", cursor), Source: "journald", Cursor: cursor, ObservedAt: at, Data: p})
	}
	return b
}
func oldJournal(t *testing.T) (*Store, string, telemetry.Batch) {
	t.Helper()
	ctx := context.Background()
	s, e := Open(ctx, filepath.Join(t.TempDir(), "events.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	dir := filepath.Join(t.TempDir(), "archives")
	if e = s.ConfigureArchive(dir); e != nil {
		t.Fatal(e)
	}
	b := journalBatch("agent-1", 0, 2, time.Now().UTC().Add(-72*time.Hour))
	if _, e = s.Accept(ctx, b.AgentID, "asset", b); e != nil {
		t.Fatal(e)
	}
	if e = s.Step(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("UPDATE raw_events SET received_at=?", stamp(time.Now().UTC().Add(-72*time.Hour))); e != nil {
		t.Fatal(e)
	}
	p := telemetry.RetentionPolicy{Enabled: true, HotDays: 1, ArchiveDays: 2, Version: 1}
	if e = s.SetRetention(ctx, p, "root", time.Now()); e != nil {
		t.Fatal(e)
	}
	return s, dir, b
}
func TestServerSearchFiltersUnicodeLiteralPaginationAndTimes(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	at := time.Now().UTC().Add(-48 * time.Hour)
	for i := 0; i < 2; i++ {
		b := journalBatch("agent-1", i*100, 75, at)
		if _, e = s.Accept(ctx, b.AgentID, "asset", b); e != nil {
			t.Fatal(e)
		}
	}
	for i := 0; i < 2; i++ {
		if e = s.Step(ctx); e != nil {
			t.Fatal(e)
		}
	}
	q := telemetry.Query{Text: "ОШИБКА ПОДКЛЮЧЕНИЯ", Source: "journald", AgentID: "agent-1", Class: "system", Outcome: "unknown", Limit: 100}
	items, e := s.ReadEvents(ctx, q)
	if e != nil || len(items) != 100 {
		t.Fatal(len(items), e)
	}
	q.Before = items[99].Sequence
	items, e = s.ReadEvents(ctx, q)
	if e != nil || len(items) != 50 {
		t.Fatal("server pagination", len(items), e)
	}
	for _, text := range []string{`ошибка OR missing`, `%`, `" OR ""`} {
		items, e = s.ReadEvents(ctx, telemetry.Query{Text: text, Limit: 100})
		if e != nil || len(items) != 0 {
			t.Fatal("literal search", text, len(items), e)
		}
	}
	items, e = s.ReadEvents(ctx, telemetry.Query{Text: "needle-private", Limit: 100})
	if e != nil || len(items) != 100 {
		t.Fatal("raw field search", len(items), e)
	}
	from := time.Now().UTC().Add(-time.Hour)
	q = telemetry.Query{From: &from, Limit: 100}
	items, e = s.ReadEvents(ctx, q)
	if e != nil || len(items) != 0 {
		t.Fatal("event timestamp", len(items), e)
	}
	q.TimeField = "received"
	items, e = s.ReadEvents(ctx, q)
	if e != nil || len(items) != 100 {
		t.Fatal("received timestamp", len(items), e)
	}
	for _, q := range []telemetry.Query{{Limit: 100, SourceIP: "bad"}, {Limit: 100, From: &from, Until: &from}, {Limit: 100, Text: strings.Repeat("a", 1025)}, {Limit: 100, Source: "syslog"}, {Limit: 100, TimeField: "sql"}} {
		if _, e = s.ReadEvents(ctx, q); !errors.Is(e, telemetry.ErrInvalid) {
			t.Fatal(q, e)
		}
	}
	b := batch(t, "win", 1000, "failure", "success")
	if _, e = s.Accept(ctx, "win", "asset", b); e != nil {
		t.Fatal(e)
	}
	s.Step(ctx)
	items, e = s.ReadEvents(ctx, telemetry.Query{AgentID: "win", User: `LAB\ALICE`, Code: "4625", SourceIP: "::ffff:10.1.2.3", Outcome: "failure", Limit: 100})
	if e != nil || len(items) != 1 {
		t.Fatal("identity filters", len(items), e)
	}
}
func TestArchivePreservesEvidenceReplayAndExpiry(t *testing.T) {
	ctx := context.Background()
	s, dir, b := oldJournal(t)
	now := time.Now().UTC()
	audit := batch(t, "win", 0, "audit")
	p := map[string]any{}
	json.Unmarshal(audit.Records[0].Data, &p)
	p["time"] = now.Add(-72 * time.Hour).Format(time.RFC3339Nano)
	audit.Records[0].Data, _ = json.Marshal(p)
	if _, e := s.Accept(ctx, "win", "asset", audit); e != nil {
		t.Fatal(e)
	}
	s.Step(ctx)
	s.db.Exec("UPDATE raw_events SET received_at=?", stamp(now.Add(-72*time.Hour)))
	detections, _ := s.ReadDetections(ctx, 0, 100)
	if len(detections) != 1 {
		t.Fatal(detections)
	}
	if e := s.Acknowledge(ctx, detections[0].ID, "analyst"); e != nil {
		t.Fatal(e)
	}
	n, e := s.Maintain(ctx, now)
	if e != nil || n != 2 {
		t.Fatal(n, e)
	}
	status, e := s.RetentionStatus(ctx)
	if e != nil || status.ProtectedEvents != 1 || status.Archives != 1 {
		t.Fatal(status, e)
	}
	var actual int64
	s.db.QueryRow("SELECT (SELECT COALESCE(sum(length(CAST(payload AS BLOB))),0) FROM raw_events)+(SELECT COALESCE(sum(length(CAST(receipt AS BLOB))+256),0) FROM batch_receipts)").Scan(&actual)
	if actual != status.QuotaBytes {
		t.Fatal("quota accounting", actual, status.QuotaBytes)
	}
	items, e := s.ReadEvents(ctx, telemetry.Query{Text: "ошибка", Limit: 100})
	if e != nil || len(items) != 0 {
		t.Fatal("search index not retired", len(items), e)
	}
	id := telemetry.ID(b.AgentID, b.Records[0].ID)
	raw, e := s.ReadRaw(ctx, id)
	if e != nil || !raw.Archived || raw.Raw.Cursor != b.Records[0].Cursor {
		t.Fatal(raw, e)
	}
	archives, e := s.Archives(ctx, 0)
	if e != nil || len(archives) != 1 {
		t.Fatal(archives, e)
	}
	data, meta, e := s.ReadArchive(ctx, archives[0].ID)
	if e != nil || len(data) == 0 || meta.Records != 2 {
		t.Fatal(meta, e)
	}
	if _, e = s.ReadRaw(ctx, detections[0].Evidence[0]); e != nil {
		t.Fatal("evidence lost", e)
	}
	b.ID = telemetry.ID("replay")
	b.Records[0].ObservedAt = now
	if _, e = s.Accept(ctx, b.AgentID, "asset", b); e != nil {
		t.Fatal("archived replay", e)
	}
	q, _ := s.Status(ctx)
	if q.Raw != 1 {
		t.Fatal("resurrected retired events", q)
	}
	b.ID = telemetry.ID("changed-replay")
	b.Records[0].Data = json.RawMessage(`{"MESSAGE":"changed"}`)
	if _, e = s.Accept(ctx, b.AgentID, "asset", b); !errors.Is(e, telemetry.ErrConflict) {
		t.Fatal("changed archived identity", e)
	}
	if _, e = s.Maintain(ctx, now.Add(3*24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(dir, meta.ID+".jsonl.gz")); !os.IsNotExist(e) {
		t.Fatal("expired file remains", e)
	}
	if _, e = s.ReadRaw(ctx, id); !errors.Is(e, telemetry.ErrExpired) {
		t.Fatal("expiry must be explicit", e)
	}
	if _, e = s.ReadRaw(ctx, detections[0].Evidence[0]); e != nil {
		t.Fatal("protected evidence expired", e)
	}
}
func TestArchiveFailureRollsBackDeletionAndAudit(t *testing.T) {
	ctx := context.Background()
	s, dir, _ := oldJournal(t)
	if _, e := s.db.Exec(`CREATE TRIGGER fail_archive_audit BEFORE INSERT ON event_retention_audit WHEN NEW.action='events.archived' BEGIN SELECT RAISE(ABORT,'fixture');END;`); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Maintain(ctx, time.Now()); e == nil {
		t.Fatal("audit failure not propagated")
	}
	v, _ := s.Status(ctx)
	if v.Raw != 2 || v.Normalized != 2 {
		t.Fatal("uncommitted archive deleted hot events", v)
	}
	a, _ := s.Archives(ctx, 0)
	if len(a) != 0 {
		t.Fatal("rolled back archive indexed", a)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl.gz"))
	if len(files) != 1 {
		t.Fatal("durable orphan retained for recovery", files)
	}
	status, _ := s.RetentionStatus(ctx)
	if status.LastError == "" {
		t.Fatal("maintenance failure hidden")
	}
	s.db.Exec("DROP TRIGGER fail_archive_audit")
	if n, e := s.Maintain(ctx, time.Now()); e != nil || n != 2 {
		t.Fatal("retry", n, e)
	}
	status, _ = s.RetentionStatus(ctx)
	if status.LastError != "" {
		t.Fatal("success did not clear failure")
	}
}
func TestArchiveCorruptionAndPendingConsumerAreNotDeleted(t *testing.T) {
	ctx := context.Background()
	s, dir, b := oldJournal(t)
	s.db.Exec("UPDATE consumer_cursors SET position=0 WHERE name='correlator/1'")
	if n, e := s.Maintain(ctx, time.Now()); e != nil || n != 0 {
		t.Fatal("unprocessed deletion", n, e)
	}
	s.Step(ctx)
	if n, e := s.Maintain(ctx, time.Now()); e != nil || n != 2 {
		t.Fatal(n, e)
	}
	a, _ := s.Archives(ctx, 0)
	path := filepath.Join(dir, a[0].ID+".jsonl.gz")
	if e := os.WriteFile(path, []byte("corrupt"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e := s.ReadArchive(ctx, a[0].ID); e == nil {
		t.Fatal("corrupt download accepted")
	}
	if _, e := s.ReadRaw(ctx, telemetry.ID(b.AgentID, b.Records[0].ID)); e == nil {
		t.Fatal("corrupt source fabricated")
	}
	if _, e := s.Maintain(ctx, time.Now().Add(4*24*time.Hour)); e == nil {
		t.Fatal("corrupt archive silently expired")
	}
	if _, e := os.Stat(path); e != nil {
		t.Fatal("corrupt evidence erased", e)
	}
}
func TestRetentionPolicyVersionAndDefaultOff(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	v, _ := s.RetentionStatus(ctx)
	if v.Policy.Enabled || v.Policy.Version != 1 || v.ArchiveConfigured {
		t.Fatal(v)
	}
	p := v.Policy
	p.Enabled = true
	if e = s.SetRetention(ctx, p, "root", time.Now()); !errors.Is(e, telemetry.ErrInvalid) {
		t.Fatal("enabled without archive directory", e)
	}
	if e = s.ConfigureArchive(t.TempDir()); e != nil {
		t.Fatal(e)
	}
	if e = s.SetRetention(ctx, p, "root", time.Now()); e != nil {
		t.Fatal(e)
	}
	if e = s.SetRetention(ctx, p, "root", time.Now()); !errors.Is(e, telemetry.ErrConflict) {
		t.Fatal("lost policy update", e)
	}
	p.Version = 2
	p.HotDays = 0
	if e = s.SetRetention(ctx, p, "root", time.Now()); !errors.Is(e, telemetry.ErrInvalid) {
		t.Fatal("unbounded hot deletion", e)
	}
}

func TestV2MigrationBackfillsSearchWithoutEnablingRetention(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "event.db")
	s, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	b := journalBatch("legacy-agent", 0, 1, time.Now().Add(-time.Hour))
	if _, e = s.Accept(ctx, b.AgentID, "asset", b); e != nil {
		t.Fatal(e)
	}
	s.Step(ctx)
	_, e = s.db.Exec(`DROP TRIGGER event_search_insert;DROP TRIGGER event_search_delete;DROP TABLE event_search;DROP TABLE retired_events;DROP TABLE event_archives;DROP TABLE event_retention_audit;DROP TABLE event_retention;DROP INDEX normalized_filter_time;DROP INDEX normalized_filter_agent_time;DROP INDEX raw_received_time;DROP INDEX normalized_filter_user;DROP INDEX normalized_filter_ip;DROP INDEX normalized_filter_source;PRAGMA user_version=2;`)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	items, e := s.ReadEvents(ctx, telemetry.Query{Text: "ОШИБКА", Limit: 100})
	if e != nil || len(items) != 1 {
		t.Fatal("backfill", items, e)
	}
	v, e := s.RetentionStatus(ctx)
	if e != nil || v.Policy.Enabled || v.Policy.Version != 1 {
		t.Fatal("migration enabled cleanup", v, e)
	}
}
