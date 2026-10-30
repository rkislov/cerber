// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/sensorstate"
	"github.com/rkislov/cerber/internal/telemetry"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func monitorHeartbeat(at time.Time) ingest.Heartbeat {
	return ingest.Heartbeat{SchemaVersion: 1, AgentID: "agent", Platform: "linux", Architecture: "amd64", ObservedAt: at, CollectionStatus: "not_attempted", DeliveryStatus: "not_attempted", Events: &telemetry.CollectorHealth{Enabled: true, ObservedAt: at, Sources: []telemetry.SourceHealth{{Source: "network:netflow", State: "ok"}}, QueueKnown: true, Delivery: "idle"}, Sensor: &sensorstate.Status{StartedAt: at.Add(-time.Hour), ObservedAt: at, MonitoringVersion: 1, InputManagement: 1, Inputs: []sensorstate.Input{{ID: "ipfix", Format: "ipfix", Protocol: "udp", Listen: "127.0.0.1:4739", Enabled: true, Allow: []string{"127.0.0.1/32"}, State: "listening"}}}}
}
func saveMonitorFixture(t *testing.T, s *Store, p sensorstate.Policy) {
	t.Helper()
	b, _ := json.Marshal(p)
	if _, e := s.db.Exec(`INSERT INTO sensor_policies VALUES('agent',?,?) ON CONFLICT(agent_id) DO UPDATE SET revision=excluded.revision,payload=excluded.payload`, p.Revision, string(b)); e != nil {
		t.Fatal(e)
	}
}
func TestSensorHistoryDeltasReplayRestartAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "monitor.db")
	s, ctx, hash := healthSetup(t, path)
	defer func() { s.Close() }()
	at := time.Now().UTC().Add(-time.Minute)
	h := monitorHeartbeat(at)
	h.Sensor.Inputs[0].Counters = sensorstate.Counters{Messages: 100, Bytes: 10000}
	if _, e := s.AcceptHeartbeat(ctx, "agent", hash, h); e != nil {
		t.Fatal(e)
	}
	h.Sensor.ObservedAt = at.Add(time.Minute)
	h.ObservedAt = h.Sensor.ObservedAt
	h.Sensor.Inputs[0].Counters = sensorstate.Counters{Messages: 160, Bytes: 16000, Rejected: 3, UnknownSets: 2}
	h.Events.QueueBatches = 5
	h.Events.QueueBytes = 512
	for k := 0; k < 3; k++ {
		if _, e := s.AcceptHeartbeat(ctx, "agent", hash, h); e != nil {
			t.Fatal(e)
		}
	}
	assertHistory := func() {
		t.Helper()
		for _, period := range []string{"24h", "7d", "30d"} {
			history, e := s.SensorHistory(ctx, "agent", "", period, time.Now().UTC())
			if e != nil || len(history.Points) == 0 {
				t.Fatal(history, e)
			}
			var n, r int64
			var seconds float64
			for _, p := range history.Points {
				n += p.Messages
				r += p.Reports
				seconds += p.Seconds
			}
			if n != 60 || r != 2 || seconds != 60 {
				t.Fatal("replay counted or wrong rate", n, r, seconds)
			}
		}
	}
	assertHistory()
	s.Close()
	var e error
	s, e = Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	assertHistory()
	h.Sensor.StartedAt = h.Sensor.ObservedAt.Add(time.Second)
	h.Sensor.ObservedAt = h.Sensor.StartedAt
	h.Sensor.Inputs[0].Counters = sensorstate.Counters{Messages: 2, Bytes: 100}
	if _, e = s.AcceptHeartbeat(ctx, "agent", hash, h); e != nil {
		t.Fatal(e)
	}
	history, e := s.SensorHistory(ctx, "agent", "", "24h", time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	var n int64
	for _, p := range history.Points {
		n += p.Messages
	}
	if n != 60 {
		t.Fatal("restart fabricated rate", n)
	}
	if _, e = s.SensorHistory(ctx, "absent", "", "24h", time.Now()); e != sensorstate.ErrNotFound {
		t.Fatal(e)
	}
}
func TestSensorHistoryRetentionAndGlobalBound(t *testing.T) {
	s, ctx, _ := healthSetup(t, ":memory:")
	defer s.Close()
	now := time.Now().UTC()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	_, e = tx.Exec(`WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<200005) INSERT INTO sensor_samples(agent_id,input_id,step,bucket,messages,bytes,stored,rejected,unknown_sets,seconds,reports,queue_reports,queue_batches,queue_bytes) SELECT 'agent','input-'||x,60,?,0,0,0,0,0,60,1,1,0,0 FROM n`, now.Unix())
	if e != nil {
		t.Fatal(e)
	}
	if e = pruneSensorHistory(ctx, tx, now); e != nil {
		t.Fatal(e)
	}
	var n int
	if e = tx.QueryRow("SELECT COUNT(*) FROM sensor_samples").Scan(&n); e != nil || n != sensorHistoryRows {
		t.Fatal(n, e)
	}
	if e = pruneSensorHistory(ctx, tx, now.Add(25*time.Hour)); e != nil {
		t.Fatal(e)
	}
	tx.QueryRow("SELECT COUNT(*) FROM sensor_samples").Scan(&n)
	if n != 0 {
		t.Fatal("expired history retained", n)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
}
func TestSensorAlertLifecycleQuietDefaultsMailAndRecovery(t *testing.T) {
	s, ctx, hash := healthSetup(t, ":memory:")
	defer s.Close()
	now := time.Now().UTC()
	h := monitorHeartbeat(now)
	if _, e := s.AcceptHeartbeat(ctx, "agent", hash, h); e != nil {
		t.Fatal(e)
	}
	global := alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}
	r, e := s.EvaluateAlerts(ctx, now, global)
	if e != nil || r.Raised != 0 {
		t.Fatal("quiet default alarm", r, e)
	}
	c := sensorstate.DefaultMonitor()
	c.Watches = []sensorstate.Watch{{Input: "ipfix", Peer: "127.0.0.1", SilenceSeconds: 180}}
	p := sensorstate.Policy{Revision: 2, UpdatedAt: now.Add(-10 * time.Minute), Monitor: &sensorstate.MonitorPolicy{Revision: 2, UpdatedAt: now.Add(-10 * time.Minute), Config: c}}
	saveMonitorFixture(t, s, p)
	h.Sensor.ObservedAt = now.Add(time.Second)
	h.Sensor.AppliedRevision = 2
	h.Sensor.Watches = []sensorstate.WatchStatus{{Input: "ipfix", Peer: "127.0.0.1", Since: now.Add(-9 * time.Minute)}}
	h.Events.QueueBatches = 600
	h.Events.QueueBytes = 20 << 20
	if _, e = s.AcceptHeartbeat(ctx, "agent", hash, h); e != nil {
		t.Fatal(e)
	}
	// Completed minute aggregates contain errors; tests never generate production traffic/mail.
	_, e = s.db.Exec(`INSERT INTO sensor_samples(agent_id,input_id,step,bucket,messages,bytes,stored,rejected,unknown_sets,seconds,reports,queue_reports,queue_batches,queue_bytes) VALUES('agent','ipfix',60,?,100,1000,80,25,12,60,1,0,0,0)`, now.Truncate(time.Minute).Add(-time.Minute).Unix())
	if e != nil {
		t.Fatal(e)
	}
	r, e = s.EvaluateAlerts(ctx, now.Add(2*time.Second), global)
	if e != nil || r.Raised != 4 {
		t.Fatal(r, e)
	}
	r, e = s.EvaluateAlerts(ctx, now.Add(3*time.Second), global)
	if e != nil || r.Raised != 0 {
		t.Fatal("duplicate alerts", r, e)
	}
	mail, e := s.NotificationBatch(ctx, 0)
	if e != nil || len(mail) != 4 {
		t.Fatal(mail, e)
	}
	found := false
	for _, m := range mail {
		if strings.Contains(m.Subject, "экспортёра") && strings.Contains(m.Body, "127.0.0.1") {
			found = true
		}
	}
	if !found {
		t.Fatal("missing actionable mail evidence", mail)
	}
	// Restore traffic and clear the measured error window.
	s.db.Exec("DELETE FROM sensor_samples")
	h.Sensor.ObservedAt = now.Add(4 * time.Second)
	seen := now
	h.Sensor.Watches[0].LastSeen = &seen
	h.Events.QueueBatches = 0
	h.Events.QueueBytes = 0
	if _, e = s.AcceptHeartbeat(ctx, "agent", hash, h); e != nil {
		t.Fatal(e)
	}
	r, e = s.EvaluateAlerts(ctx, now.Add(5*time.Second), global)
	if e != nil || r.Resolved != 4 {
		t.Fatal(r, e)
	}
	active, _ := s.Alerts(ctx, "active", 0, 20)
	if len(active) != 0 {
		t.Fatal(active)
	}
	// Unapplied configuration is distinct from source silence; disabled monitoring clears it.
	p.Revision = 3
	saveMonitorFixture(t, s, p)
	r, e = s.EvaluateAlerts(ctx, now.Add(6*time.Second), global)
	if e != nil || r.Raised != 1 {
		t.Fatal(r, e)
	}
	p.Monitor.Config.Enabled = false
	saveMonitorFixture(t, s, p)
	r, e = s.EvaluateAlerts(ctx, now.Add(time.Hour), global)
	if e != nil || r.Resolved != 1 || r.Raised != 0 {
		t.Fatal("disabled monitor alarm", r, e)
	}
}
func TestSensorMigrationV13PreservesOpenAlerts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v13.db")
	s, ctx, _ := healthSetup(t, path)
	s.db.Exec(`INSERT INTO alerts(id,agent_id,asset_id,kind,severity,raised_at,evidence) VALUES('old','agent','asset','agent_offline','critical',?,'{}')`, stamp(time.Now()))
	if _, e := s.db.Exec("DROP TABLE sensor_samples; PRAGMA user_version=13"); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e := Open(context.Background(), path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	list, e := s.Alerts(ctx, "active", 0, 10)
	if e != nil || len(list) != 1 || list[0].ID != "old" {
		t.Fatal(list, e)
	}
}

func TestSensorQueueWaitsForSustainedGrowth(t *testing.T) {
	s, ctx, _ := healthSetup(t, ":memory:")
	defer s.Close()
	now := time.Now().UTC()
	h := monitorHeartbeat(now)
	h.Events.QueueBatches = 1
	a := ingest.AgentStatus{AgentID: "agent", Health: &h}
	c := sensorstate.DefaultMonitor()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	out := map[string]alerts.Evidence{}
	if e = sensorQueueConditions(ctx, tx, a, now, c, out); e != nil || len(out) != 0 {
		t.Fatal("first packet falsely alarmed", out, e)
	}
	h.Events.QueueBatches = 2
	h.Events.ObservedAt = now.Add(301 * time.Second)
	if e = sensorQueueConditions(ctx, tx, a, now.Add(301*time.Second), c, out); e != nil {
		t.Fatal(e)
	}
	if _, ok := out["event_queue_growing"]; !ok {
		t.Fatal("sustained growth missed")
	}
	if _, ok := out["event_delivery_stalled"]; !ok {
		t.Fatal("stalled delivery missed")
	}
	// A stale empty queue is unknown, not recovery: retain the observation.
	h.Events.QueueBatches = 0
	h.Events.ObservedAt = now
	out = map[string]alerts.Evidence{}
	if e = sensorQueueConditions(ctx, tx, a, now.Add(302*time.Second), c, out); e != nil {
		t.Fatal(e)
	}
	if _, ok := out["event_health_stale"]; !ok {
		t.Fatal("stale queue falsely cleared", out)
	}
	h.Events.QueueBatches = 2
	h.Events.ObservedAt = now.Add(302 * time.Second)
	out = map[string]alerts.Evidence{}
	if e = sensorQueueConditions(ctx, tx, a, now.Add(302*time.Second), c, out); e != nil {
		t.Fatal(e)
	}
	if _, ok := out["event_delivery_stalled"]; !ok {
		t.Fatal("stale queue reset delivery observation")
	}
	h.Events.QueueBatches = 0
	out = map[string]alerts.Evidence{}
	if e = sensorQueueConditions(ctx, tx, a, now.Add(302*time.Second), c, out); e != nil || len(out) != 0 {
		t.Fatal(out, e)
	}
	h.Events.QueueBatches = 1
	if e = sensorQueueConditions(ctx, tx, a, now.Add(303*time.Second), c, out); e != nil || len(out) != 0 {
		t.Fatal("queue recovery did not reset observation", out, e)
	}
}
