// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/jobs"
	"github.com/rkislov/cerber/internal/sensorstate"
	"github.com/rkislov/cerber/internal/suricatacapture"
	rules "github.com/rkislov/cerber/internal/suricatarules"
	"github.com/rkislov/cerber/internal/telemetry"
)

type rolloutFixture struct {
	t                   *testing.T
	s                   *Store
	ctx                 context.Context
	ids                 []string
	hash, group, canary string
	p                   rules.GroupPolicy
	stable, candidate   rules.Bundle
	now, started        time.Time
}

func newRolloutFixture(t *testing.T) *rolloutFixture {
	t.Helper()
	s, ctx, id, hash := ruleAutomationFixture(t)
	f := &rolloutFixture{t: t, s: s, ctx: ctx, ids: []string{id, "fleet"}, hash: hash, now: time.Now().UTC(), started: time.Now().UTC().Add(-time.Hour), stable: autoBundle(t, 1000, "custom"), candidate: autoBundle(t, 1001, "custom")}
	addGroupAgent(t, s, "fleet")
	for _, b := range []rules.Bundle{f.stable, f.candidate} {
		if _, e := s.PutSuricataBundle(ctx, b); e != nil {
			t.Fatal(e)
		}
	}
	for _, id := range f.ids {
		f.emit(id, "idle", nil)
		if _, e := s.AssignSuricata(ctx, rules.Change{AgentID: id, BundleID: f.stable.Manifest.ID}); e != nil {
			t.Fatal(e)
		}
		f.now = f.now.Add(time.Second)
		f.emit(id, "applied", nil)
	}
	g := makeGroup(t, s, f.ids...)
	f.group = g.ID
	cg, e := s.GroupCommand(ctx, jobs.GroupCommand{Action: "create", Name: "Canary"}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.GroupCommand(ctx, jobs.GroupCommand{Action: "members.add", GroupID: cg, GroupVersion: 1, AgentIDs: []string{id}}, f.now); e != nil {
		t.Fatal(e)
	}
	f.canary = cg
	f.p, e = s.SetSuricataGroup(ctx, rules.GroupChange{GroupPolicy: rules.GroupPolicy{GroupID: f.group, Enabled: true, EngineMajor: 7, Mode: "pinned", BundleID: f.stable.Manifest.ID}})
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *rolloutFixture) config() *rules.RolloutConfig {
	return &rules.RolloutConfig{CanaryGroupID: f.canary, ObservationSeconds: 60, TimeoutSeconds: 300, MaxDropPercent: 5, MaxQueueMiB: 64}
}
func (f *rolloutFixture) emit(id, state string, change func(*ingest.Heartbeat)) {
	f.t.Helper()
	a, e := f.s.SuricataAssignment(f.ctx, id)
	if e != nil {
		f.t.Fatal(e)
	}
	h := ingest.Heartbeat{SchemaVersion: 1, AgentID: id, ObservedAt: f.now, Platform: "linux", Architecture: "amd64", CollectionStatus: "not_attempted", DeliveryStatus: "not_attempted", Sensor: &sensorstate.Status{StartedAt: f.started, ObservedAt: f.now, Rules: &rules.Status{Version: 1, EngineMajor: 7, Revision: a.Revision, State: state, AppliedID: a.Bundle.ID, DesiredID: a.Bundle.ID, UpdatedAt: f.now}, Capture: &suricatacapture.Status{Version: 1, Mode: "test", Interface: "span0", State: "receiving", EVEState: "ready", ObservedAt: f.now, Uptime: uint64(f.now.Sub(f.started).Seconds()), Packets: uint64(f.now.Sub(f.started).Seconds())}, Inputs: []sensorstate.Input{{ID: "eve", Format: "suricata", Protocol: "file", Enabled: true, State: "receiving"}}}, Events: &telemetry.CollectorHealth{Enabled: true, ObservedAt: f.now, QueueKnown: true, Delivery: "idle", Sources: []telemetry.SourceHealth{{Source: "network:suricata", State: "ok"}}}}
	if change != nil {
		change(&h)
	}
	if _, e = f.s.AcceptHeartbeat(context.Background(), id, f.hash, h); e != nil {
		f.t.Fatal(e)
	}
	// Advance only the server clock used by the deterministic rollout supervisor.
	if _, e = f.s.db.Exec("UPDATE agent_heartbeats SET received_at=? WHERE agent_id=?", stamp(f.now), id); e != nil {
		f.t.Fatal(e)
	}
}
func (f *rolloutFixture) start() {
	f.t.Helper()
	var e error
	f.p, e = f.s.SetSuricataGroup(f.ctx, rules.GroupChange{ExpectedRevision: f.p.Revision, GroupPolicy: rules.GroupPolicy{GroupID: f.group, Enabled: true, EngineMajor: 7, Mode: "pinned", BundleID: f.candidate.Manifest.ID, Rollout: f.config()}})
	if e != nil {
		f.t.Fatal(e)
	}
	if f.p.State != "canary" {
		f.t.Fatal(f.p)
	}
}
func (f *rolloutFixture) tick() {
	f.t.Helper()
	if e := f.s.AdvanceSuricataRollouts(f.ctx, f.now); e != nil {
		f.t.Fatal(e)
	}
}
func (f *rolloutFixture) rollout() *rules.Rollout {
	f.t.Helper()
	r, e := readSuricataRollout(f.ctx, f.s.db, f.group)
	if e != nil || r == nil {
		f.t.Fatal(r, e)
	}
	return r
}
func (f *rolloutFixture) assignment(id string) rules.Assignment {
	a, e := f.s.SuricataAssignment(f.ctx, id)
	if e != nil {
		f.t.Fatal(e)
	}
	return a
}
func (f *rolloutFixture) healthy(seconds int) {
	f.now = f.now.Add(time.Duration(seconds) * time.Second)
	for _, id := range f.ids {
		f.emit(id, "applied", nil)
	}
	f.tick()
}

func TestSuricataRolloutCanaryGatePersistenceFleetAndCompletion(t *testing.T) {
	f := newRolloutFixture(t)
	f.start()
	f.tick()
	if f.assignment(f.ids[0]).Bundle.ID != f.candidate.Manifest.ID || f.assignment("fleet").Bundle.ID != f.stable.Manifest.ID {
		t.Fatal("canary did not fence fleet")
	}
	if e := f.s.DeleteSuricataBundle(f.ctx, f.stable.Manifest.ID); !errors.Is(e, rules.ErrConflict) {
		t.Fatal("recovery package deleted", e)
	}
	if _, e := f.s.AssignSuricata(f.ctx, rules.Change{AgentID: f.ids[0], ExpectedRevision: f.assignment(f.ids[0]).Revision, BundleID: f.stable.Manifest.ID}); !errors.Is(e, rules.ErrConflict) {
		t.Fatal("manual bypass", e)
	}
	f.healthy(1)
	f.healthy(30)
	if f.rollout().State != "canary" {
		t.Fatal("early promotion")
	}
	reopened, e := Open(f.ctx, f.s.Path())
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	f.s = reopened
	f.healthy(31)
	if f.rollout().State != "fleet" {
		t.Fatal(f.rollout())
	}
	f.tick()
	if f.assignment("fleet").Bundle.ID != f.candidate.Manifest.ID {
		t.Fatal("fleet not assigned")
	}
	f.healthy(1)
	f.healthy(61)
	r := f.rollout()
	if r.State != "completed" {
		t.Fatal(r)
	}
	p, _ := readSuricataGroup(f.ctx, f.s.db, f.group)
	if p.ActiveID != f.candidate.Manifest.ID || p.PreviousID != f.stable.Manifest.ID || p.State != "ready" {
		t.Fatal(p)
	}
	rev := f.assignment("fleet").Revision
	f.tick()
	if f.assignment("fleet").Revision != rev {
		t.Fatal("repeated assignment")
	}
}
func TestSuricataRolloutFailedCanaryFencesCandidateAndRestoresBaseline(t *testing.T) {
	f := newRolloutFixture(t)
	f.start()
	f.tick()
	candidateRevision := f.assignment(f.ids[0]).Revision
	f.now = f.now.Add(time.Second)
	f.emit(f.ids[0], "error", func(h *ingest.Heartbeat) {
		h.Sensor.Rules.AppliedID = f.stable.Manifest.ID
		h.Sensor.Rules.Error = "invalid syntax"
	})
	f.tick()
	r := f.rollout()
	a := f.assignment(f.ids[0])
	if r.State != "rolling_back" || a.Bundle.ID != f.stable.Manifest.ID || a.Revision <= candidateRevision {
		t.Fatal(r, a)
	}
	if f.assignment("fleet").Bundle.ID != f.stable.Manifest.ID {
		t.Fatal("failed canary reached fleet")
	}
	f.healthy(1)
	if f.rollout().State != "rolled_back" {
		t.Fatal(f.rollout())
	}
	p, _ := readSuricataGroup(f.ctx, f.s.db, f.group)
	if p.Mode != "pinned" || p.ActiveID != f.stable.Manifest.ID {
		t.Fatal(p)
	}
}
func TestSuricataRolloutHealthFailureDuringFleetRollsBackEveryTouchedSensor(t *testing.T) {
	for _, fault := range []string{"delivery", "capture", "queue", "drops", "restart", "stale"} {
		t.Run(fault, func(t *testing.T) {
			f := newRolloutFixture(t)
			f.start()
			f.tick()
			f.healthy(1)
			f.healthy(61)
			f.tick()
			f.healthy(1)
			if f.rollout().State != "fleet" {
				t.Fatal(f.rollout())
			}
			f.now = f.now.Add(time.Second)
			f.emit(f.ids[0], "applied", func(h *ingest.Heartbeat) {
				switch fault {
				case "delivery":
					h.Events.Delivery = "error"
				case "capture":
					h.Sensor.Capture.State = "unavailable"
				case "queue":
					h.Events.QueueBytes = 65 << 20
				case "drops":
					h.Sensor.Capture.Dropped = 100
				case "restart":
					h.Sensor.Capture.Uptime = 1
				case "stale":
					h.Sensor.Capture.ObservedAt = f.now.Add(-time.Hour)
				}
			})
			f.tick()
			if f.rollout().State != "rolling_back" {
				t.Fatal(f.rollout())
			}
			for _, id := range f.ids {
				if f.assignment(id).Bundle.ID != f.stable.Manifest.ID {
					t.Fatal("not rolled back", id)
				}
			}
		})
	}
}
func TestSuricataRolloutOfflineTimeoutFailedRollbackAndExplicitRetry(t *testing.T) {
	f := newRolloutFixture(t)
	f.start()
	f.tick()
	f.now = f.now.Add(181 * time.Second)
	f.tick()
	if f.rollout().State != "rolling_back" {
		t.Fatal(f.rollout())
	}
	f.now = f.now.Add(301 * time.Second)
	f.tick()
	if f.rollout().State != "rollback_failed" {
		t.Fatal(f.rollout())
	}
	p, _ := readSuricataGroup(f.ctx, f.s.db, f.group)
	old := f.assignment(f.ids[0]).Revision
	f.healthy(1) // Recovery alone never silently retries an unsuccessful rollback.
	if f.rollout().State != "rollback_failed" {
		t.Fatal("unrequested retry")
	}
	_, e := f.s.SetSuricataGroup(f.ctx, rules.GroupChange{ExpectedRevision: p.Revision, GroupPolicy: rules.GroupPolicy{GroupID: f.group}, RetryRollback: true})
	if e != nil {
		t.Fatal(e)
	}
	if f.assignment(f.ids[0]).Revision <= old {
		t.Fatal("retry did not fence failed attempt")
	}
	// SetSuricataGroup uses the actual server clock; align its new deadline with
	// this test's simulated supervisor time before advancing the next sample.
	if _, e = f.s.db.Exec(`UPDATE suricata_rollouts SET payload=json_set(payload,'$.stage_started_at',?) WHERE group_id=?`, stamp(f.now), f.group); e != nil {
		t.Fatal(e)
	}
	f.healthy(1)
	if f.rollout().State != "rolled_back" {
		t.Fatal(f.rollout())
	}
}
func TestSuricataRolloutNoPromotionOnCachedHeartbeatsAndNoClockOnlySuccess(t *testing.T) {
	f := newRolloutFixture(t)
	f.start()
	f.tick()
	f.healthy(1)
	f.now = f.now.Add(61 * time.Second)
	f.tick()
	if f.rollout().State != "canary" {
		t.Fatal("wall clock promoted without samples")
	}
	f.healthy(1)
	if f.rollout().State != "fleet" {
		t.Fatal(f.rollout())
	}
}
func TestSuricataRolloutMembershipSnapshotAndCancellationCAS(t *testing.T) {
	f := newRolloutFixture(t)
	f.start()
	f.tick()
	g, _ := f.s.AgentGroup(f.ctx, f.group)
	if _, e := f.s.GroupCommand(f.ctx, jobs.GroupCommand{Action: "members.remove", GroupID: g.ID, GroupVersion: g.Version, AgentIDs: []string{f.ids[0]}}, f.now); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.AssignSuricata(f.ctx, rules.Change{AgentID: f.ids[0], ExpectedRevision: f.assignment(f.ids[0]).Revision, BundleID: f.stable.Manifest.ID}); !errors.Is(e, rules.ErrConflict) {
		t.Fatal("membership removal bypass", e)
	}
	if _, e := f.s.SetSuricataGroup(f.ctx, rules.GroupChange{ExpectedRevision: f.p.Revision - 1, GroupPolicy: rules.GroupPolicy{GroupID: f.group}, Rollback: true}); !errors.Is(e, rules.ErrConflict) {
		t.Fatal("stale cancel", e)
	}
	if _, e := f.s.SetSuricataGroup(f.ctx, rules.GroupChange{ExpectedRevision: f.p.Revision, GroupPolicy: rules.GroupPolicy{GroupID: f.group}, Rollback: true}); e != nil {
		t.Fatal(e)
	}
	f.healthy(1)
	if f.rollout().State != "rolled_back" {
		t.Fatal(f.rollout())
	}
}
func TestSuricataRolloutBlocksMissingDiagnosticsAndInvalidCanary(t *testing.T) {
	f := newRolloutFixture(t)
	bad := f.config()
	bad.CanaryGroupID = f.group
	if _, e := f.s.SetSuricataGroup(f.ctx, rules.GroupChange{ExpectedRevision: f.p.Revision, GroupPolicy: rules.GroupPolicy{GroupID: f.group, Enabled: true, EngineMajor: 7, Mode: "pinned", BundleID: f.candidate.Manifest.ID, Rollout: bad}}); !errors.Is(e, rules.ErrInvalid) {
		t.Fatal(e)
	}
	f.now = f.now.Add(time.Second)
	f.emit(f.ids[0], "applied", func(h *ingest.Heartbeat) { h.Sensor.Capture = nil })
	p, e := f.s.SetSuricataGroup(f.ctx, rules.GroupChange{ExpectedRevision: f.p.Revision, GroupPolicy: rules.GroupPolicy{GroupID: f.group, Enabled: true, EngineMajor: 7, Mode: "pinned", BundleID: f.candidate.Manifest.ID, Rollout: f.config()}})
	if e != nil || p.State != "blocked" || !strings.Contains(p.Error, "диагностики") {
		t.Fatal(p, e)
	}
	f.tick()
	for _, id := range f.ids {
		if f.assignment(id).Bundle.ID != f.stable.Manifest.ID {
			t.Fatal("blocked rollout assigned")
		}
	}
}
func TestSuricataRolloutAutomaticFeedFencesNewCandidates(t *testing.T) {
	f := newRolloutFixture(t)
	_, e := f.s.SetSuricataGroup(f.ctx, rules.GroupChange{ExpectedRevision: f.p.Revision, GroupPolicy: rules.GroupPolicy{GroupID: f.group, Enabled: true, EngineMajor: 7, Mode: "et_open", Rollout: f.config()}})
	if e != nil {
		t.Fatal(e)
	}
	b := autoBundle(t, 2000, "et-open")
	publishFeed(t, f.s, f.ctx, b)
	download := func(context.Context, int) (rules.Bundle, error) {
		t.Fatal("unexpected download")
		return rules.Bundle{}, nil
	}
	if e = rules.Tick(f.ctx, f.s, download); e != nil {
		t.Fatal(e)
	}
	r := f.rollout()
	if r.State != "canary" || r.CandidateID != b.Manifest.ID {
		t.Fatal(r)
	}
	publishFeed(t, f.s, f.ctx, autoBundle(t, 2001, "et-open"))
	if e = rules.Tick(f.ctx, f.s, download); e != nil {
		t.Fatal(e)
	}
	if f.rollout().ID != r.ID {
		t.Fatal("in-flight rollout replaced")
	}
	// Its own immutable baseline is protected even if assignment pointers change.
	payload, _ := json.Marshal(r)
	if !strings.Contains(string(payload), f.stable.Manifest.ID) {
		t.Fatal("missing rollback pin")
	}
}

func TestSuricataRolloutKeepsPerSensorBaselineAndDoesNotReloadIdenticalRules(t *testing.T) {
	f := newRolloutFixture(t)
	// Before group ownership is reconciled, model a fleet sensor already running
	// the candidate. Its previous version must not be replaced by the canary's.
	a := f.assignment("fleet")
	candidate, e := f.s.SuricataBundle(f.ctx, f.candidate.Manifest.ID)
	if e != nil {
		t.Fatal(e)
	}
	a.Bundle = candidate.Manifest
	a.Revision++
	data, _ := json.Marshal(a)
	if _, e = f.s.db.Exec("UPDATE suricata_assignments SET payload=? WHERE agent_id='fleet'", string(data)); e != nil {
		t.Fatal(e)
	}
	// Keep this accepted telemetry consistent without invoking normal group fanout.
	var raw string
	f.s.db.QueryRow("SELECT payload FROM agent_heartbeats WHERE agent_id='fleet'").Scan(&raw)
	var h ingest.Heartbeat
	json.Unmarshal([]byte(raw), &h)
	h.Sensor.Rules.AppliedID = a.Bundle.ID
	h.Sensor.Rules.DesiredID = a.Bundle.ID
	h.Sensor.Rules.Revision = a.Revision
	data, _ = json.Marshal(h)
	if _, e = f.s.db.Exec("UPDATE agent_heartbeats SET payload=? WHERE agent_id='fleet'", string(data)); e != nil {
		t.Fatal(e)
	}
	f.start()
	f.tick()
	f.healthy(1)
	f.healthy(61)
	f.tick()
	if f.assignment("fleet").Revision != a.Revision {
		t.Fatal("identical package reloaded")
	}
	f.now = f.now.Add(time.Second)
	f.emit(f.ids[0], "applied", func(h *ingest.Heartbeat) { h.Events.Delivery = "error" })
	f.tick()
	if f.assignment(f.ids[0]).Bundle.ID != f.stable.Manifest.ID || f.assignment("fleet").Bundle.ID != f.candidate.Manifest.ID {
		t.Fatal("per-sensor baseline lost")
	}
	f.healthy(1)
	if f.rollout().State != "rolled_back" {
		t.Fatal(f.rollout())
	}
}
func TestSuricataRolloutLongObservationGapRestartsHealthWindow(t *testing.T) {
	f := newRolloutFixture(t)
	f.start()
	f.tick()
	f.healthy(1)
	f.healthy(181)
	r := f.rollout()
	if r.State != "canary" {
		t.Fatal("unobserved gap counted as healthy", r)
	}
	for _, m := range r.Members {
		if m.Phase == "canary" && m.Samples != 1 {
			t.Fatal(m)
		}
	}
	f.healthy(61)
	if f.rollout().State != "fleet" {
		t.Fatal(f.rollout())
	}
}
func TestSuricataRolloutRevocationCannotProduceFalseRollbackSuccess(t *testing.T) {
	f := newRolloutFixture(t)
	f.start()
	f.tick()
	if e := f.s.RevokeAgent(f.ctx, f.ids[0]); e != nil {
		t.Fatal(e)
	}
	f.tick()
	r := f.rollout()
	if r.State != "rollback_failed" {
		t.Fatal(r)
	}
	if r.Members[0].State != "rollback_failed" {
		t.Fatal(r.Members)
	}
}
