// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"errors"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/jobs"
	"strings"
	"testing"
	"time"
)

func makeGroup(t *testing.T, s *Store, agents ...string) jobs.Group {
	t.Helper()
	ctx := context.Background()
	id, err := s.GroupCommand(ctx, jobs.GroupCommand{Action: "create", Name: "Fixture group"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) > 0 {
		if _, err = s.GroupCommand(ctx, jobs.GroupCommand{Action: "members.add", GroupID: id, GroupVersion: 1, AgentIDs: agents}, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	g, err := s.AgentGroup(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func addGroupAgent(t *testing.T, s *Store, id string) {
	t.Helper()
	assets, e := s.Assets(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e = s.RegisterAgent(context.Background(), id, assets[0].ID, ingest.Hash([]byte(strings.Repeat("a", 64)))); e != nil {
		t.Fatal(e)
	}
}
func TestGroupFanoutSnapshotsSkipsAndProgress(t *testing.T) {
	ctx := context.Background()
	s, a, hash := jobFixture(t)
	addGroupAgent(t, s, "revoked")
	addGroupAgent(t, s, "full")
	addGroupAgent(t, s, "later")
	g := makeGroup(t, s, a, "revoked", "full")
	now := time.Now().UTC()
	if e := s.RevokeAgent(ctx, "revoked"); e != nil {
		t.Fatal(e)
	}
	for range 20 {
		if _, e := s.JobCommand(ctx, jobs.Command{Action: "run", AgentID: "full", Kind: "inventory"}, now); e != nil {
			t.Fatal(e)
		}
	}
	run, e := s.GroupCommand(ctx, jobs.GroupCommand{Action: "run", GroupID: g.ID, GroupVersion: g.Version, Kind: "updates"}, now)
	if e != nil {
		t.Fatal(e)
	}
	summary, e := s.AgentGroupRun(ctx, run)
	if e != nil || summary.Total != 3 || summary.Queued != 1 || summary.Skipped != 2 || summary.State != "queued" {
		t.Fatal(summary, e)
	}
	members, e := s.GroupRunMembers(ctx, run, "", 101)
	if e != nil || len(members) != 3 {
		t.Fatal(members, e)
	}
	reasons := map[string]string{}
	for _, m := range members {
		reasons[m.AgentID] = m.SkipReason
	}
	if reasons["revoked"] != "agent_revoked" || reasons["full"] != "queue_full" {
		t.Fatal(reasons)
	}
	if _, e = s.GroupCommand(ctx, jobs.GroupCommand{Action: "members.remove", GroupID: g.ID, GroupVersion: g.Version, AgentIDs: []string{a}}, now); e != nil {
		t.Fatal(e)
	}
	g, _ = s.AgentGroup(ctx, g.ID)
	if _, e = s.GroupCommand(ctx, jobs.GroupCommand{Action: "members.add", GroupID: g.ID, GroupVersion: g.Version, AgentIDs: []string{"later"}}, now); e != nil {
		t.Fatal(e)
	}
	members, _ = s.GroupRunMembers(ctx, run, "", 101)
	if len(members) != 3 {
		t.Fatal("changed snapshot")
	}
	for _, m := range members {
		if m.AgentID == "later" {
			t.Fatal("expanded existing run")
		}
	}
	j, e := s.ClaimJob(ctx, a, hash, now)
	if e != nil || j == nil || j.GroupRunID != run {
		t.Fatal(j, e)
	}
	summary, _ = s.AgentGroupRun(ctx, run)
	if summary.Running != 1 || summary.State != "running" {
		t.Fatal(summary)
	}
	if e = s.FinishJob(ctx, a, hash, jobs.Result{JobID: j.ID, Status: "failed", Code: "collection_failed"}, now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	summary, _ = s.AgentGroupRun(ctx, run)
	if summary.Failed != 1 || summary.Skipped != 2 || summary.State != "failed" {
		t.Fatal(summary)
	}
}
func TestGroupSchedulesUseCurrentMembersAndDoNotBlockHealthyAgents(t *testing.T) {
	ctx := context.Background()
	s, a, hash := jobFixture(t)
	addGroupAgent(t, s, "new-agent")
	g := makeGroup(t, s, a)
	now := time.Now().UTC()
	schedule, e := s.GroupCommand(ctx, jobs.GroupCommand{Action: "schedule.create", GroupID: g.ID, GroupVersion: g.Version, Kind: "inventory", IntervalSeconds: 60, FirstRunAt: now}, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.AdvanceJobs(ctx, now); e != nil {
		t.Fatal(e)
	}
	runs, _ := s.GroupRuns(ctx, g.ID, 0, 101)
	if len(runs) != 1 || runs[0].Total != 1 {
		t.Fatal(runs)
	}
	first := runs[0].ID
	if _, e = s.GroupCommand(ctx, jobs.GroupCommand{Action: "members.add", GroupID: g.ID, GroupVersion: g.Version, AgentIDs: []string{"new-agent"}}, now); e != nil {
		t.Fatal(e)
	}
	g, _ = s.AgentGroup(ctx, g.ID)
	if e = s.AdvanceJobs(ctx, now.Add(10*time.Minute)); e != nil {
		t.Fatal(e)
	}
	runs, _ = s.GroupRuns(ctx, g.ID, 0, 101)
	if len(runs) != 2 || runs[0].Total != 2 || runs[0].Queued != 1 || runs[0].Skipped != 1 || runs[1].ID != first || runs[1].Total != 1 {
		t.Fatal("missed intervals or membership", runs)
	}
	members, _ := s.GroupRunMembers(ctx, runs[0].ID, "", 101)
	for _, m := range members {
		if m.AgentID == a && m.SkipReason != "previous_run_pending" {
			t.Fatal(m)
		}
	}
	schedules, _ := s.GroupSchedules(ctx, g.ID, "", 101)
	if !schedules[0].NextRunAt.Equal(now.Add(11 * time.Minute)) {
		t.Fatal(schedules)
	}
	// Completing one agent does not wait for the unavailable member of previous runs.
	j, e := s.ClaimJob(ctx, a, hash, now.Add(10*time.Minute))
	if e != nil || j == nil {
		t.Fatal(e)
	}
	if e = s.FinishJob(ctx, a, hash, jobs.Result{JobID: j.ID, Status: "failed", Code: "collection_failed"}, now.Add(10*time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e = s.AdvanceJobs(ctx, now.Add(11*time.Minute)); e != nil {
		t.Fatal(e)
	}
	runs, _ = s.GroupRuns(ctx, g.ID, 0, 101)
	if len(runs) != 3 || runs[0].Queued != 1 || runs[0].Skipped != 1 {
		t.Fatal(runs)
	}
	if _, e = s.GroupCommand(ctx, jobs.GroupCommand{Action: "archive", GroupID: g.ID, GroupVersion: g.Version}, now); e != nil {
		t.Fatal(e)
	}
	schedules, _ = s.GroupSchedules(ctx, g.ID, "", 101)
	if schedules[0].Enabled {
		t.Fatal("archive did not pause schedule")
	}
	g, _ = s.AgentGroup(ctx, g.ID)
	if _, e = s.GroupCommand(ctx, jobs.GroupCommand{Action: "restore", GroupID: g.ID, GroupVersion: g.Version}, now); e != nil {
		t.Fatal(e)
	}
	schedules, _ = s.GroupSchedules(ctx, g.ID, "", 101)
	if schedules[0].Enabled {
		t.Fatal("restore resumed unexpectedly")
	}
	if schedules[0].ID != schedule {
		t.Fatal(schedules)
	}
}
func TestGroupVersionsRBACAndAuditRollback(t *testing.T) {
	ctx := context.Background()
	s, a, _ := jobFixture(t)
	g := makeGroup(t, s, a)
	now := time.Now().UTC()
	password, _ := admin.HashPassword("fixture-password-123")
	for _, u := range []admin.User{{Username: "root", Role: "administrator"}, {Username: "reader", Role: "viewer"}, {Username: "operator", Role: "operator"}} {
		if e := s.AdminCommand(ctx, admin.Command{Action: "user.create", Username: u.Username, Role: u.Role, PasswordHash: password}); e != nil {
			t.Fatal(e)
		}
	}
	reader, _ := s.AdminUser(ctx, "reader")
	reader.Role = "administrator"
	if _, e := s.GroupCommand(admin.WithPrincipal(ctx, reader), jobs.GroupCommand{Action: "run", GroupID: g.ID, GroupVersion: g.Version, Kind: "inventory"}, now); !errors.Is(e, admin.ErrForbidden) {
		t.Fatal(e)
	}
	op, _ := s.AdminUser(ctx, "operator")
	opCtx := admin.WithPrincipal(ctx, op)
	if _, e := s.GroupCommand(opCtx, jobs.GroupCommand{Action: "run", GroupID: g.ID, GroupVersion: g.Version - 1, Kind: "inventory"}, now); !errors.Is(e, domain.ErrConflict) {
		t.Fatal("stale group version", e)
	}
	if _, e := s.db.Exec(`CREATE TRIGGER fail_batch BEFORE INSERT ON outbox WHEN NEW.kind='agent.group.run.created' BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
		t.Fatal(e)
	}
	if _, e := s.GroupCommand(opCtx, jobs.GroupCommand{Action: "run", GroupID: g.ID, GroupVersion: g.Version, Kind: "inventory"}, now); e == nil {
		t.Fatal("accepted without audit")
	}
	runs, _ := s.GroupRuns(ctx, g.ID, 0, 101)
	childJobs, _ := s.Jobs(ctx, a, 0, 101)
	if len(runs) != 0 || len(childJobs) != 0 {
		t.Fatal("partial fanout", runs, childJobs)
	}
	s.db.Exec("DROP TRIGGER fail_batch")
	run, e := s.GroupCommand(opCtx, jobs.GroupCommand{Action: "run", GroupID: g.ID, GroupVersion: g.Version, Kind: "inventory"}, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.GroupCommand(opCtx, jobs.GroupCommand{Action: "run.cancel", ID: run}, now); e != nil {
		t.Fatal(e)
	}
	summary, _ := s.AgentGroupRun(ctx, run)
	if summary.Canceled != 1 || summary.State != "canceled" {
		t.Fatal(summary)
	}
	events, _ := s.Events(ctx, 0, 1000)
	canceled := 0
	for _, event := range events {
		if event.Kind == "agent.job.canceled" {
			canceled++
		}
	}
	if canceled != 1 {
		t.Fatal("missing child cancellation audit", canceled)
	}
}
func TestGroupMemberLimitAndMigration(t *testing.T) {
	ctx := context.Background()
	s, a, hash := jobFixture(t)
	g := makeGroup(t, s)
	now := time.Now().UTC()
	assets, _ := s.Assets(ctx)
	if _, e := s.db.Exec(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<501) INSERT INTO agents(id,asset_id,token_hash,created_at) SELECT printf('limit-%03d',x),?,?,? FROM n`, assets[0].ID, hash, stamp(now)); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec(`INSERT INTO agent_group_members SELECT ?,id,? FROM agents WHERE id LIKE 'limit-%' AND id<>'limit-501'`, g.ID, stamp(now)); e != nil {
		t.Fatal(e)
	}
	if _, e := s.GroupCommand(ctx, jobs.GroupCommand{Action: "members.add", GroupID: g.ID, GroupVersion: g.Version, AgentIDs: []string{"limit-501"}}, now); !errors.Is(e, domain.ErrConflict) {
		t.Fatal("unbounded group", e)
	}
	after, _ := s.AgentGroup(ctx, g.ID)
	if after.Members != 500 || after.Version != g.Version {
		t.Fatal("limit mutation not rolled back", after)
	}
	// Starting from a v8 database keeps agent jobs and the local journal intact.
	oldJob, e := s.JobCommand(ctx, jobs.Command{Action: "run", AgentID: a, Kind: "inventory"}, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.StartLocalJob(ctx, a, oldJob); e != nil {
		t.Fatal(e)
	}
	var seq int
	var name, path string
	s.db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path)
	if _, e = s.db.Exec("DROP TABLE agent_group_run_members; DROP TABLE agent_group_runs; DROP TABLE agent_group_schedules; DROP TABLE agent_group_members; DROP TABLE agent_groups; PRAGMA user_version=8"); e != nil {
		t.Fatal(e)
	}
	s.Close()
	reopened, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	rows, e := reopened.Jobs(ctx, a, 0, 101)
	if e != nil || len(rows) != 1 || rows[0].ID != oldJob || rows[0].GroupRunID != "" {
		t.Fatal(rows, e)
	}
	journal, e := reopened.LocalJob(ctx, a)
	if e != nil || journal.JobID != oldJob {
		t.Fatal(journal, e)
	}
}
