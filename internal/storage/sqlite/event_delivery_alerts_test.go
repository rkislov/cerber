// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/telemetry"
	"path/filepath"
	"testing"
	"time"
)

func TestDeliveryObservationSurvivesRestartAndRecovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "health.db")
	s, ctx, _ := healthSetup(t, path)
	now := time.Now().UTC()
	hb := now
	a := ingest.AgentStatus{AgentID: "agent", LastHeartbeatAt: &hb, Health: &ingest.Heartbeat{Events: &telemetry.CollectorHealth{Enabled: true, ObservedAt: now, QueueKnown: true, QueueBatches: 10, QueueBytes: 100, Delivery: "error"}}}
	check := func(at time.Time) map[string]alerts.Evidence {
		t.Helper()
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		out := map[string]alerts.Evidence{}
		if e = eventDeliveryConditions(ctx, tx, a, at, out); e != nil {
			tx.Rollback()
			t.Fatal(e)
		}
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
		return out
	}
	if out := check(now); len(out) != 0 {
		t.Fatal("initial transient alert", out)
	}
	s.Close()
	var e error
	s, e = Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	hb = now.Add(6 * time.Minute)
	a.Health.Events.ObservedAt = hb
	a.Health.Events.QueueBatches = 20
	out := check(hb)
	if _, ok := out["event_delivery_stalled"]; !ok {
		t.Fatal(out)
	}
	if _, ok := out["event_queue_growing"]; !ok {
		t.Fatal(out)
	}
	a.Health.Events.QueueBatches = 0
	if out = check(hb); len(out) != 0 {
		t.Fatal(out)
	}
	a.Health.Events.QueueBatches = 2
	hb = hb.Add(time.Minute)
	a.Health.Events.ObservedAt = hb
	if out = check(hb); len(out) != 0 {
		t.Fatal("recovery left stale observation", out)
	}
	a.Revoked = true
	if out = check(hb.Add(time.Hour)); len(out) != 0 {
		t.Fatal(out)
	}
}

func TestDeliveryAlertPersistsNotifiesAndResolves(t *testing.T) {
	s, ctx, hash := healthSetup(t, filepath.Join(t.TempDir(), "alerts.db"))
	defer s.Close()
	now := time.Now().UTC()
	h := ingest.Heartbeat{SchemaVersion: 1, AgentID: "agent", ObservedAt: now, Platform: "linux", Architecture: "amd64", CollectionStatus: "complete", DeliveryStatus: "ok", Events: &telemetry.CollectorHealth{Enabled: true, ObservedAt: now, QueueKnown: true, QueueBatches: 10, QueueBytes: 100, Delivery: "error", Sources: []telemetry.SourceHealth{{Source: "journald", State: "ok"}}}}
	if _, e := s.AcceptHeartbeat(ctx, "agent", hash, h); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec("INSERT INTO event_delivery_observations VALUES(?,?,?)", "agent", stamp(now.Add(-6*time.Minute)), int64(10)); e != nil {
		t.Fatal(e)
	}
	p := alerts.Policy{OfflineAfter: time.Hour, InventoryMaxAge: 24 * time.Hour}
	if _, e := s.EvaluateAlerts(ctx, now, p); e != nil {
		t.Fatal(e)
	}
	list, e := s.Alerts(ctx, "active", 0, 10)
	if e != nil || len(list) != 1 || list[0].Kind != "event_delivery_stalled" {
		t.Fatal(list, e)
	}
	notices, e := s.NotificationBatch(ctx, 0)
	if e != nil || len(notices) != 1 {
		t.Fatal(notices, e)
	}
	if notices[0].Details.Kind != "alert" || notices[0].Details.Title != alerts.Title(list[0].Kind) || notices[0].Details.Severity != list[0].Severity || notices[0].Details.OccurredAt.IsZero() {
		t.Fatal("notification lost alert context", notices[0].Details)
	}
	if _, e = s.EvaluateAlerts(ctx, now, p); e != nil {
		t.Fatal(e)
	}
	list, _ = s.Alerts(ctx, "active", 0, 10)
	if len(list) != 1 {
		t.Fatal("duplicate alert")
	}
	h.Events.QueueBatches = 0
	h.Events.Delivery = "ok"
	if _, e = s.AcceptHeartbeat(ctx, "agent", hash, h); e != nil {
		t.Fatal(e)
	}
	if _, e = s.EvaluateAlerts(ctx, now, p); e != nil {
		t.Fatal(e)
	}
	list, _ = s.Alerts(ctx, "active", 0, 10)
	if len(list) != 0 {
		t.Fatal("recovery did not resolve alert")
	}
}
