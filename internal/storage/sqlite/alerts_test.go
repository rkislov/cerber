// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"errors"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/inventory"
	"path/filepath"
	"testing"
	"time"
)

func TestAlertLifecyclePersistenceRecoveryAndAcknowledgement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.db")
	s, ctx, hash := healthSetup(t, path)
	now := time.Now().UTC()
	policy := alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}
	if _, err := s.db.Exec("UPDATE agents SET created_at=?", stamp(now.Add(-2*time.Hour))); err != nil {
		t.Fatal(err)
	}
	result, err := s.EvaluateAlerts(ctx, now, policy)
	if err != nil || result.Raised != 2 {
		t.Fatal(result, err)
	}
	items, _ := s.Alerts(ctx, "active", 0, 10)
	if len(items) != 2 || !items[0].Evidence.Missing {
		t.Fatal(items)
	}
	id := items[0].ID
	first, err := s.AcknowledgeAlert(ctx, id, "administrator")
	if err != nil || first.AcknowledgedAt == nil {
		t.Fatal(first, err)
	}
	events, _ := s.Events(ctx, 0, 100)
	if _, err = s.AcknowledgeAlert(ctx, id, "administrator"); err != nil {
		t.Fatal(err)
	}
	again, _ := s.Events(ctx, 0, 100)
	if len(again) != len(events) {
		t.Fatal("ack duplicated audit")
	}
	s.Close()
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	result, err = s.EvaluateAlerts(ctx, now.Add(time.Second), policy)
	if err != nil || result.Raised != 0 || result.Resolved != 0 {
		t.Fatal("restart duplicated alerts", result, err)
	}
	h := ingest.Heartbeat{SchemaVersion: 1, AgentID: "agent", ObservedAt: now, Platform: "linux", Architecture: "arm64", CollectionStatus: "partial", DeliveryStatus: "ok"}
	if _, err = s.AcceptHeartbeat(ctx, "agent", hash, h); err != nil {
		t.Fatal(err)
	}
	result, err = s.EvaluateAlerts(ctx, time.Now(), policy)
	if err != nil || result.Resolved != 1 {
		t.Fatal(result, err)
	}
	items, _ = s.Alerts(ctx, "active", 0, 10)
	if len(items) != 1 || items[0].Kind != "inventory_stale" {
		t.Fatal(items)
	}
	r := ingest.Report{SchemaVersion: 1, AgentID: "agent", ID: "old", Snapshot: inventory.Snapshot{SchemaVersion: 1, ID: "old", AssetID: "local", Collector: "fixture", CollectedAt: now.Add(-3 * time.Hour), Coverage: []inventory.Coverage{{Section: "os", Status: "error"}}}}
	if _, err = s.AcceptReport(ctx, "agent", hash, r); err != nil {
		t.Fatal(err)
	}
	result, err = s.EvaluateAlerts(ctx, time.Now(), policy)
	if err != nil || result.Resolved != 0 {
		t.Fatal("old inventory cleared alert", result, err)
	}
	r.ID = "new"
	r.Snapshot.ID = "new"
	r.Snapshot.CollectedAt = time.Now().UTC()
	if _, err = s.AcceptReport(ctx, "agent", hash, r); err != nil {
		t.Fatal(err)
	}
	result, err = s.EvaluateAlerts(ctx, time.Now(), policy)
	if err != nil || result.Resolved != 1 {
		t.Fatal(result, err)
	}
	resolved, _ := s.Alerts(ctx, "resolved", 0, 10)
	if len(resolved) != 2 {
		t.Fatal(resolved)
	}
	if _, err = s.db.Exec("UPDATE agent_status SET last_seen_at=?", stamp(now.Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	result, err = s.EvaluateAlerts(ctx, time.Now(), policy)
	if err != nil || result.Raised != 1 {
		t.Fatal(result, err)
	}
	items, _ = s.Alerts(ctx, "active", 0, 10)
	if items[0].ID == id || items[0].AcknowledgedAt != nil {
		t.Fatal("new incident inherited acknowledgement")
	}
	if err = s.RevokeAgent(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	result, err = s.EvaluateAlerts(ctx, time.Now(), policy)
	if err != nil || result.Resolved != 1 || result.Raised != 0 {
		t.Fatal(result, err)
	}
	items, _ = s.Alerts(ctx, "active", 0, 10)
	if len(items) != 0 {
		t.Fatal(items)
	}
}
func TestAlertGraceRollbackAndMigration(t *testing.T) {
	s, ctx, _ := healthSetup(t, ":memory:")
	defer s.Close()
	p := alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}
	now := time.Now()
	r, err := s.EvaluateAlerts(ctx, now, p)
	if err != nil || r.Raised != 0 {
		t.Fatal("new enrollment alerted without grace", r, err)
	}
	if _, err = s.db.Exec("UPDATE agents SET created_at=?", stamp(now.Add(-2*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`CREATE TRIGGER reject_alert BEFORE INSERT ON outbox WHEN NEW.kind='alert.raised' BEGIN SELECT RAISE(ABORT,'test'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.EvaluateAlerts(ctx, now, p); err == nil {
		t.Fatal("outbox failure ignored")
	}
	items, _ := s.Alerts(ctx, "all", 0, 10)
	if len(items) != 0 {
		t.Fatal("alert committed without event")
	}
	if _, err = s.AcknowledgeAlert(ctx, "missing", "cli"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal(err)
	}
}
func TestV5MigrationKeepsAgentState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v5.db")
	s, ctx, _ := healthSetup(t, path)
	if _, err := s.db.Exec("DROP TABLE alerts"); err != nil {
		t.Fatal(err)
	}
	s.db.Exec("PRAGMA user_version=5")
	s.Close()
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	states, err := s.AgentStatuses(ctx, "", "", 10)
	if err != nil || len(states) != 1 {
		t.Fatal(states, err)
	}
	if _, err = s.Alerts(ctx, "active", 0, 10); err != nil {
		t.Fatal(err)
	}
}
