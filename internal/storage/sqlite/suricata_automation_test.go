// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/jobs"
	"github.com/rkislov/cerber/internal/sensorstate"
	rules "github.com/rkislov/cerber/internal/suricatarules"
)

func ruleAutomationFixture(t *testing.T) (*Store, context.Context, string, string) {
	t.Helper()
	s, id, hash := jobFixture(t)
	pw, _ := admin.HashPassword("automation-fixture-password")
	if e := s.AdminCommand(context.Background(), admin.Command{Action: "user.create", Username: "owner", Role: "administrator", PasswordHash: pw}); e != nil {
		t.Fatal(e)
	}
	ctx := admin.WithPrincipal(context.Background(), admin.User{Username: "owner", Role: "administrator", Version: 1})
	return s, ctx, id, hash
}
func autoBundle(t *testing.T, sid int, source string) rules.Bundle {
	t.Helper()
	b, e := rules.Pack(fmt.Sprint("fixture", sid), source, 7, []byte(fmt.Sprintf(`alert icmp any any -> any any (msg:"fixture"; sid:%d; rev:1;)`, sid)))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func publishFeed(t *testing.T, s *Store, ctx context.Context, b rules.Bundle) rules.Feed {
	t.Helper()
	fs, e := s.SuricataFeeds(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.SetSuricataFeed(ctx, rules.FeedChange{EngineMajor: 7, ExpectedRevision: fs[0].Revision, RunNow: true})
	if e != nil {
		t.Fatal(e)
	}
	task, e := s.ClaimSuricataFeed(ctx, time.Now().UTC())
	if e != nil || task == nil {
		t.Fatal(task, e)
	}
	if e = s.CompleteSuricataFeed(ctx, *task, b, nil, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	fs, _ = s.SuricataFeeds(ctx)
	return fs[0]
}
func rulesHeartbeat(t *testing.T, s *Store, id, hash string, a rules.Assignment, state string) rules.Assignment {
	t.Helper()
	now := time.Now().UTC()
	h := ingest.Heartbeat{SchemaVersion: 1, AgentID: id, Platform: "linux", Architecture: "amd64", ObservedAt: now, CollectionStatus: "not_attempted", DeliveryStatus: "not_attempted", Sensor: &sensorstate.Status{StartedAt: now, ObservedAt: now, Rules: &rules.Status{Version: 1, EngineMajor: 7, State: state, UpdatedAt: now, Revision: a.Revision, AppliedID: a.Bundle.ID, DesiredID: a.Bundle.ID}}}
	r, e := s.AcceptHeartbeat(context.Background(), id, hash, h)
	if e != nil {
		t.Fatal(e)
	}
	if r.Suricata != nil {
		return *r.Suricata
	}
	return rules.Assignment{}
}
func TestSuricataScheduleDurableLeaseFenceFailureAndCoalescing(t *testing.T) {
	s, ctx, _, _ := ruleAutomationFixture(t)
	now := time.Now().UTC()
	f, e := s.SetSuricataFeed(ctx, rules.FeedChange{EngineMajor: 7, Enabled: true, IntervalHours: 24, NextRunAt: now})
	if e != nil {
		t.Fatal(e)
	}
	task, e := s.ClaimSuricataFeed(ctx, now.Add(72*time.Hour))
	if e != nil || task == nil {
		t.Fatal(task, e)
	}
	if other, e := s.ClaimSuricataFeed(ctx, now.Add(72*time.Hour)); e != nil || other != nil {
		t.Fatal("double claim", other, e)
	}
	// A new store process sees the same lease, and an expired claim gets a new token.
	reopened, e := Open(ctx, s.Path())
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	newer, e := reopened.ClaimSuricataFeed(ctx, now.Add(72*time.Hour+6*time.Minute))
	if e != nil || newer == nil || newer.Lease == task.Lease {
		t.Fatal(newer, e)
	}
	b := autoBundle(t, 1, "et-open")
	if e = s.CompleteSuricataFeed(ctx, *task, b, nil, now.Add(72*time.Hour+6*time.Minute)); !errors.Is(e, rules.ErrConflict) {
		t.Fatal("stale completion", e)
	}
	if e = reopened.CompleteSuricataFeed(ctx, *newer, b, nil, now.Add(72*time.Hour+6*time.Minute)); e != nil {
		t.Fatal(e)
	}
	fs, _ := s.SuricataFeeds(ctx)
	if fs[0].LatestID != b.Manifest.ID || !fs[0].NextRunAt.Equal(now.Add(96*time.Hour)) {
		t.Fatal(fs[0])
	}
	f = publishFeed(t, s, ctx, b)
	if f.State != "unchanged" {
		t.Fatal(f)
	}
	f, e = s.SetSuricataFeed(ctx, rules.FeedChange{EngineMajor: 7, ExpectedRevision: f.Revision, RunNow: true})
	if e != nil {
		t.Fatal(e)
	}
	task, _ = s.ClaimSuricataFeed(ctx, time.Now())
	if e = s.CompleteSuricataFeed(ctx, *task, rules.Bundle{}, fmt.Errorf("fixture upstream failure"), time.Now()); e != nil {
		t.Fatal(e)
	}
	fs, _ = s.SuricataFeeds(ctx)
	if fs[0].LatestID != b.Manifest.ID || fs[0].State != "error" {
		t.Fatal(fs[0])
	}
	f, e = s.SetSuricataFeed(ctx, rules.FeedChange{EngineMajor: 7, ExpectedRevision: f.Revision, RunNow: true})
	if e != nil {
		t.Fatal(e)
	}
	task, _ = s.ClaimSuricataFeed(ctx, time.Now())
	_, e = s.SetSuricataFeed(ctx, rules.FeedChange{EngineMajor: 7, ExpectedRevision: f.Revision, Enabled: false, IntervalHours: 24, NextRunAt: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteSuricataFeed(ctx, *task, autoBundle(t, 2, "et-open"), nil, time.Now()); !errors.Is(e, rules.ErrConflict) {
		t.Fatal("disabled schedule published", e)
	}
}
func TestSuricataGroupAutomaticOverlayMembershipAndRollback(t *testing.T) {
	s, ctx, id, hash := ruleAutomationFixture(t)
	g := makeGroup(t, s, id)
	a := autoBundle(t, 100, "custom")
	custom := autoBundle(t, 1000001, "custom")
	for _, b := range []rules.Bundle{a, custom} {
		if _, e := s.PutSuricataBundle(ctx, b); e != nil {
			t.Fatal(e)
		}
	}
	rulesHeartbeat(t, s, id, hash, rules.Assignment{}, "idle")
	p, e := s.SetSuricataGroup(ctx, rules.GroupChange{GroupPolicy: rules.GroupPolicy{GroupID: g.ID, Enabled: true, EngineMajor: 7, Mode: "pinned", BundleID: a.Manifest.ID}})
	if e != nil {
		t.Fatal(e)
	}
	assigned := rulesHeartbeat(t, s, id, hash, rules.Assignment{}, "idle")
	if assigned.Bundle.ID != a.Manifest.ID || assigned.GroupID != g.ID {
		t.Fatal(assigned)
	}
	rulesHeartbeat(t, s, id, hash, assigned, "applied")
	if _, e = s.AssignSuricata(ctx, rules.Change{AgentID: id, ExpectedRevision: assigned.Revision, BundleID: a.Manifest.ID}); !errors.Is(e, rules.ErrConflict) {
		t.Fatal("individual write bypassed group", e)
	}
	p, e = s.SetSuricataGroup(ctx, rules.GroupChange{ExpectedRevision: p.Revision, GroupPolicy: rules.GroupPolicy{GroupID: g.ID, Enabled: true, EngineMajor: 7, Mode: "et_open", CustomID: custom.Manifest.ID}})
	if e != nil {
		t.Fatal(e)
	}
	et := autoBundle(t, 200, "et-open")
	publishFeed(t, s, ctx, et)
	download := func(context.Context, int) (rules.Bundle, error) {
		t.Fatal("unexpected HTTP")
		return rules.Bundle{}, nil
	}
	if e = rules.Tick(context.Background(), s, download); e != nil {
		t.Fatal(e)
	}
	views, _ := s.SuricataGroups(ctx)
	p = views[0].Policy
	if p.State != "ready" || p.PreviousID != a.Manifest.ID || p.BuiltETID != et.Manifest.ID {
		t.Fatal(p)
	}
	b, e := s.SuricataBundle(ctx, p.ActiveID)
	if e != nil || b.Manifest.Count != 2 {
		t.Fatal(b.Manifest, e)
	}
	next := rulesHeartbeat(t, s, id, hash, assigned, "applied")
	if next.Bundle.ID != p.ActiveID || next.Revision != assigned.Revision+1 {
		t.Fatal(next)
	}
	rulesHeartbeat(t, s, id, hash, next, "applied")
	if same := rulesHeartbeat(t, s, id, hash, next, "applied"); same.Revision != next.Revision {
		t.Fatal("repeated assignment", same)
	}
	// Newly enrolled group members receive the active policy on their first heartbeat.
	addGroupAgent(t, s, "later")
	g, _ = s.AgentGroup(ctx, g.ID)
	if _, e = s.GroupCommand(ctx, jobs.GroupCommand{Action: "members.add", GroupID: g.ID, GroupVersion: g.Version, AgentIDs: []string{"later"}}, time.Now()); e != nil {
		t.Fatal(e)
	}
	late := rulesHeartbeat(t, s, "later", hash, rules.Assignment{}, "idle")
	if late.Bundle.ID != p.ActiveID {
		t.Fatal(late)
	}
	rollback, e := s.SetSuricataGroup(ctx, rules.GroupChange{GroupPolicy: rules.GroupPolicy{GroupID: g.ID}, ExpectedRevision: p.Revision, Rollback: true})
	if e != nil || rollback.Mode != "pinned" || rollback.ActiveID != a.Manifest.ID {
		t.Fatal(rollback, e)
	}
	if got := rulesHeartbeat(t, s, id, hash, next, "applied"); got.Bundle.ID != a.Manifest.ID {
		t.Fatal(got)
	}
	publishFeed(t, s, ctx, autoBundle(t, 201, "et-open"))
	if e = rules.Tick(ctx, s, download); e != nil {
		t.Fatal(e)
	}
	views, _ = s.SuricataGroups(ctx)
	if views[0].Policy.ActiveID != a.Manifest.ID {
		t.Fatal("rollback was overwritten")
	}
	if e = s.DeleteSuricataBundle(ctx, a.Manifest.ID); !errors.Is(e, rules.ErrConflict) {
		t.Fatal("active deleted", e)
	}
}
func TestSuricataGroupConflictsRevocationAndInvalidOverlay(t *testing.T) {
	s, ctx, id, hash := ruleAutomationFixture(t)
	g := makeGroup(t, s, id)
	b := autoBundle(t, 1, "custom")
	s.PutSuricataBundle(ctx, b)
	rulesHeartbeat(t, s, id, hash, rules.Assignment{}, "idle")
	p, e := s.SetSuricataGroup(ctx, rules.GroupChange{GroupPolicy: rules.GroupPolicy{GroupID: g.ID, Enabled: true, EngineMajor: 7, Mode: "pinned", BundleID: b.Manifest.ID}})
	if e != nil {
		t.Fatal(e)
	}
	assigned := rulesHeartbeat(t, s, id, hash, rules.Assignment{}, "idle")
	rulesHeartbeat(t, s, id, hash, assigned, "applied")
	// A SID collision fails the group build while preserving its active package.
	p, e = s.SetSuricataGroup(ctx, rules.GroupChange{ExpectedRevision: p.Revision, GroupPolicy: rules.GroupPolicy{GroupID: g.ID, Enabled: true, EngineMajor: 7, Mode: "et_open", CustomID: b.Manifest.ID}})
	if e != nil {
		t.Fatal(e)
	}
	publishFeed(t, s, ctx, autoBundle(t, 1, "et-open"))
	download := func(context.Context, int) (rules.Bundle, error) { return rules.Bundle{}, errors.New("unexpected") }
	if e = rules.Tick(ctx, s, download); e != nil {
		t.Fatal(e)
	}
	views, _ := s.SuricataGroups(ctx)
	p = views[0].Policy
	if p.State != "error" || p.ActiveID != b.Manifest.ID || p.Error == "" {
		t.Fatal(p)
	}
	history, _ := s.SuricataAutomationHistory(ctx, g.ID)
	rules.Tick(ctx, s, download)
	after, _ := s.SuricataAutomationHistory(ctx, g.ID)
	if len(after) != len(history) {
		t.Fatal("repeated bad build")
	}
	id2, e := s.GroupCommand(ctx, jobs.GroupCommand{Action: "create", Name: "Overlapping"}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	s.GroupCommand(ctx, jobs.GroupCommand{Action: "members.add", GroupID: id2, GroupVersion: 1, AgentIDs: []string{id}}, time.Now())
	s.SetSuricataGroup(ctx, rules.GroupChange{GroupPolicy: rules.GroupPolicy{GroupID: id2, Enabled: true, EngineMajor: 7, Mode: "pinned", BundleID: b.Manifest.ID}})
	got := rulesHeartbeat(t, s, id, hash, assigned, "applied")
	if got.Revision != assigned.Revision {
		t.Fatal("conflicting groups reassigned", got)
	}
	views, _ = s.SuricataGroups(ctx)
	for _, v := range views {
		if v.Members[0].State != "conflict" {
			t.Fatal(v)
		}
	}
	s.RevokeAgent(ctx, id)
	views, _ = s.SuricataGroups(ctx)
	if views[0].Members[0].State != "revoked" {
		t.Fatal(views)
	}
}
func TestSuricataAutomaticRetentionProtectsManualAndReferencedVersions(t *testing.T) {
	s, ctx, _, _ := ruleAutomationFixture(t)
	custom := autoBundle(t, 999, "custom")
	if _, e := s.PutSuricataBundle(ctx, custom); e != nil {
		t.Fatal(e)
	}
	first := publishFeed(t, s, ctx, autoBundle(t, 10, "et-open"))
	g := makeGroup(t, s)
	p, e := s.SetSuricataGroup(ctx, rules.GroupChange{GroupPolicy: rules.GroupPolicy{GroupID: g.ID, Enabled: true, EngineMajor: 7, Mode: "pinned", BundleID: first.LatestID}})
	if e != nil {
		t.Fatal(e)
	}
	for i := 11; i < 28; i++ {
		f := publishFeed(t, s, ctx, autoBundle(t, i, "et-open"))
		if f.State == "error" {
			t.Fatal(f)
		}
	}
	versions, _, e := s.SuricataCatalog(ctx)
	if e != nil || len(versions) != rules.MaxVersions {
		t.Fatal(len(versions), e)
	}
	for _, id := range []string{custom.Manifest.ID, p.ActiveID} {
		if _, e = s.SuricataBundle(ctx, id); e != nil {
			t.Fatal("protected version pruned", id, e)
		}
	}
	if e = s.DeleteSuricataBundle(ctx, p.ActiveID); !errors.Is(e, rules.ErrConflict) {
		t.Fatal(e)
	}
}

func TestSuricataGroupOwnershipAndExplicitFailureRetry(t *testing.T) {
	s, ctx, id, hash := ruleAutomationFixture(t)
	g := makeGroup(t, s, id)
	b := autoBundle(t, 901, "custom")
	if _, e := s.PutSuricataBundle(ctx, b); e != nil {
		t.Fatal(e)
	}
	rulesHeartbeat(t, s, id, hash, rules.Assignment{}, "idle")
	a, e := s.AssignSuricata(ctx, rules.Change{AgentID: id, BundleID: b.Manifest.ID})
	if e != nil {
		t.Fatal(e)
	}
	rulesHeartbeat(t, s, id, hash, a, "applied")
	change := rules.GroupChange{GroupPolicy: rules.GroupPolicy{GroupID: g.ID, Enabled: true, EngineMajor: 7, Mode: "pinned", BundleID: b.Manifest.ID}}
	p, e := s.SetSuricataGroup(ctx, change)
	if e != nil {
		t.Fatal(e)
	}
	owned := rulesHeartbeat(t, s, id, hash, a, "applied")
	if owned.Revision != a.Revision || owned.GroupID != g.ID || owned.GroupRevision != p.Revision {
		t.Fatal("ownership reloaded existing rules", owned)
	}
	// Neither failed nor healthy steady-state heartbeats create new attempts.
	if got := rulesHeartbeat(t, s, id, hash, owned, "error"); got.Revision != owned.Revision {
		t.Fatal("unrequested retry", got)
	}
	change.ExpectedRevision = p.Revision
	p, e = s.SetSuricataGroup(ctx, change)
	if e != nil {
		t.Fatal(e)
	}
	if got := rulesHeartbeat(t, s, id, hash, owned, "rollback_failed"); got.Revision != owned.Revision {
		t.Fatal("unresolved rollback retried", got)
	}
	retried := rulesHeartbeat(t, s, id, hash, owned, "error")
	if retried.Revision != owned.Revision+1 || retried.GroupRevision != p.Revision {
		t.Fatal("explicit retry missing", retried)
	}
	if got := rulesHeartbeat(t, s, id, hash, retried, "error"); got.Revision != retried.Revision {
		t.Fatal("failed retry loop", got)
	}
	change.ExpectedRevision = p.Revision
	if _, e = s.SetSuricataGroup(ctx, change); e != nil {
		t.Fatal(e)
	}
	if got := rulesHeartbeat(t, s, id, hash, retried, "applied"); got.Revision != retried.Revision {
		t.Fatal("healthy unchanged rules reloaded", got)
	}
}
