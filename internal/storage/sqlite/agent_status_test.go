// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/event"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/inventory"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func healthSetup(t *testing.T, path string) (*Store, context.Context, string) {
	t.Helper()
	ctx := context.Background()
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	asset := domain.Asset{ID: "asset", IP: "127.0.0.1", CreatedAt: time.Now().UTC()}
	e, _ := event.New("asset.created", asset.ID, asset)
	if err = s.CreateAsset(ctx, asset, e); err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("a", 64)
	if err = s.RegisterAgent(ctx, "agent", asset.ID, hash); err != nil {
		t.Fatal(err)
	}
	return s, ctx, hash
}
func TestHeartbeatTransactionRollback(t *testing.T) {
	s, ctx, hash := healthSetup(t, ":memory:")
	defer s.Close()
	if _, err := s.db.Exec(`CREATE TRIGGER reject_health_event BEFORE INSERT ON outbox WHEN NEW.kind='agent.health_changed' BEGIN SELECT RAISE(ABORT,'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	h := ingest.Heartbeat{SchemaVersion: 1, AgentID: "agent", ObservedAt: time.Now(), Platform: "linux", Architecture: "arm64", CollectionStatus: "error", DeliveryStatus: "error"}
	if _, err := s.AcceptHeartbeat(ctx, "agent", hash, h); err == nil {
		t.Fatal("event failure did not abort health")
	}
	values, err := s.AgentStatuses(ctx, "", "", 100)
	if err != nil || values[0].LastSeenAt != nil || values[0].Health != nil {
		t.Fatal(values, err)
	}
}
func TestMigrateV4BackfillsAgentHistoryAndDuplicateContact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v4.db")
	s, ctx, hash := healthSetup(t, path)
	now := time.Now().UTC()
	latest := now.Add(-time.Hour)
	makeReport := func(id string, at time.Time) ingest.Report {
		return ingest.Report{SchemaVersion: 1, ID: id, AgentID: "agent", Snapshot: inventory.Snapshot{SchemaVersion: 1, ID: id, AssetID: "local", CollectedAt: at, Collector: "fixture", Coverage: []inventory.Coverage{{Section: "os", Status: "error"}}}}
	}
	newer := makeReport("newer", latest)
	first, err := s.AcceptReport(ctx, "agent", hash, newer)
	if err != nil {
		t.Fatal(err)
	}
	older := makeReport("older", now.Add(-24*time.Hour))
	second, err := s.AcceptReport(ctx, "agent", hash, older)
	if err != nil {
		t.Fatal(err)
	}
	// Same-second times that sort incorrectly as raw variable-width RFC3339 text.
	first.ReceivedAt = now.Add(-time.Minute).Truncate(time.Second)
	second.ReceivedAt = first.ReceivedAt.Add(100 * time.Millisecond)
	for _, r := range []ingest.Receipt{first, second} {
		data, _ := json.Marshal(r)
		if _, err = s.db.Exec("UPDATE agent_receipts SET receipt=? WHERE agent_id='agent' AND report_id=?", string(data), r.ReportID); err != nil {
			t.Fatal(err)
		}
	}
	for _, query := range []string{"DROP TABLE agent_heartbeats", "DROP TABLE agent_status", "PRAGMA user_version=4"} {
		if _, err = s.db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	values, err := s.AgentStatuses(ctx, "", "", 100)
	if err != nil || len(values) != 1 {
		t.Fatal(values, err)
	}
	v := values[0]
	if v.LastSeenAt == nil || !v.LastSeenAt.Equal(second.ReceivedAt) || v.LatestInventoryID != first.SnapshotID || !v.LatestInventoryAt.Equal(latest) {
		t.Fatal(v)
	}
	events, _ := s.Events(ctx, 0, 100)
	duplicate, err := s.AcceptReport(ctx, "agent", hash, older)
	if err != nil || !duplicate.Duplicate {
		t.Fatal(duplicate, err)
	}
	values, _ = s.AgentStatuses(ctx, "", "", 100)
	if !values[0].LastSeenAt.After(second.ReceivedAt) || values[0].LatestInventoryID != first.SnapshotID {
		t.Fatal(values)
	}
	after, _ := s.Events(ctx, 0, 100)
	if len(events) != len(after) {
		t.Fatal("duplicate emitted events")
	}
}
