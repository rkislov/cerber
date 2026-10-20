// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"errors"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/app"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/jobs"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func jobFixture(t *testing.T) (*Store, string, string) {
	t.Helper()
	ctx := context.Background()
	s, e := Open(ctx, filepath.Join(t.TempDir(), "server.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	asset, e := (app.Service{Repo: s}).AddAsset(ctx, "192.0.2.1", "fixture")
	if e != nil {
		t.Fatal(e)
	}
	hash := ingest.Hash([]byte(strings.Repeat("a", 64)))
	if e = s.RegisterAgent(ctx, "agent", asset.ID, hash); e != nil {
		t.Fatal(e)
	}
	return s, "agent", hash
}
func TestScheduleCoalescingLeaseAndRevocation(t *testing.T) {
	ctx := context.Background()
	s, id, hash := jobFixture(t)
	now := time.Now().UTC()
	schedule, err := s.JobCommand(ctx, jobs.Command{Action: "schedule.create", AgentID: id, Kind: "updates", FirstRunAt: now.Add(time.Minute), IntervalSeconds: 60}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AdvanceJobs(ctx, now); err != nil {
		t.Fatal(err)
	}
	runs, _ := s.Jobs(ctx, "", 0, 101)
	if len(runs) != 0 {
		t.Fatal("premature schedule")
	}
	if err = s.AdvanceJobs(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = s.AdvanceJobs(ctx, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	runs, _ = s.Jobs(ctx, id, 0, 101)
	schedules, _ := s.JobSchedules(ctx, id, "", 101)
	if len(runs) != 1 || runs[0].ScheduleID != schedule || len(schedules) != 1 || !schedules[0].NextRunAt.Equal(now.Add(11*time.Minute)) {
		t.Fatal("backlog coalescing", runs, schedules)
	}
	job, err := s.ClaimJob(ctx, id, hash, now.Add(10*time.Minute))
	if err != nil || job == nil {
		t.Fatal(job, err)
	}
	result := jobs.Result{JobID: job.ID, Status: "failed", Code: "collection_failed"}
	if err = s.FinishJob(ctx, id, hash, result, now.Add(20*time.Minute)); !errors.Is(err, jobs.ErrTerminal) {
		t.Fatal("lease expiration", err)
	}
	if err = s.AdvanceJobs(ctx, now.Add(21*time.Minute)); err != nil {
		t.Fatal(err)
	}
	runs, _ = s.Jobs(ctx, id, 0, 101)
	if len(runs) != 2 || runs[1].State != "timed_out" || runs[0].State != "queued" {
		t.Fatal(runs)
	}
	if err = s.RevokeAgent(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ClaimJob(ctx, id, hash, now.Add(21*time.Minute)); !errors.Is(err, ingest.ErrUnauthorized) {
		t.Fatal(err)
	}
	if err = s.AdvanceJobs(ctx, now.Add(22*time.Minute)); err != nil {
		t.Fatal(err)
	}
	runs, _ = s.Jobs(ctx, id, 0, 101)
	schedules, _ = s.JobSchedules(ctx, id, "", 101)
	if runs[0].State != "canceled" || schedules[0].Enabled {
		t.Fatal("revoked work remains enabled", runs, schedules)
	}
	if _, err = s.JobCommand(ctx, jobs.Command{Action: "run", AgentID: id, Kind: "inventory"}, now); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("revoked enqueue", err)
	}
}
func TestJobClaimsAreExclusiveAndCompletionIdempotent(t *testing.T) {
	ctx := context.Background()
	s, id, hash := jobFixture(t)
	now := time.Now().UTC()
	jobID, err := s.JobCommand(ctx, jobs.Command{Action: "run", AgentID: id, Kind: "inventory"}, now)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan *jobs.Job, 10)
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j, e := s.ClaimJob(ctx, id, hash, now)
			if e != nil {
				t.Error(e)
			}
			results <- j
		}()
	}
	wg.Wait()
	close(results)
	count := 0
	for j := range results {
		if j != nil {
			count++
		}
	}
	if count != 1 {
		t.Fatal("duplicate claim", count)
	}
	if err = s.FinishJob(ctx, id, hash, jobs.Result{JobID: jobID, Status: "succeeded", Code: "complete", ReportID: "not-received"}, now.Add(time.Second)); !errors.Is(err, jobs.ErrReportPending) {
		t.Fatal("success without report", err)
	}
	result := jobs.Result{JobID: jobID, Status: "failed", Code: "collection_failed"}
	if err = s.FinishJob(ctx, id, hash, result, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishJob(ctx, id, hash, result, now.Add(24*time.Hour)); err != nil {
		t.Fatal("lost acknowledgement retry", err)
	}
	result.Code = "interrupted"
	if err = s.FinishJob(ctx, id, hash, result, now.Add(time.Second)); !errors.Is(err, jobs.ErrTerminal) {
		t.Fatal("rewrote terminal result", err)
	}
	events, _ := s.Events(ctx, 0, 1000)
	n := 0
	for _, e := range events {
		if e.Kind == "agent.job.failed" {
			n++
		}
	}
	if n != 1 {
		t.Fatal("duplicate completion event", n)
	}
}
func TestJobRBACCancellationAndAtomicAudit(t *testing.T) {
	ctx := context.Background()
	s, id, hash := jobFixture(t)
	now := time.Now().UTC()
	password, _ := admin.HashPassword("fixture-password-123")
	for _, u := range []admin.User{{Username: "root", Role: "administrator"}, {Username: "reader", Role: "viewer"}, {Username: "operator", Role: "operator"}} {
		if err := s.AdminCommand(ctx, admin.Command{Action: "user.create", Username: u.Username, Role: u.Role, PasswordHash: password}); err != nil {
			t.Fatal(err)
		}
	}
	reader, _ := s.AdminUser(ctx, "reader")
	reader.Role = "administrator"
	if _, err := s.JobCommand(admin.WithPrincipal(ctx, reader), jobs.Command{Action: "run", AgentID: id, Kind: "inventory"}, now); !errors.Is(err, admin.ErrForbidden) {
		t.Fatal("forged role", err)
	}
	operator, _ := s.AdminUser(ctx, "operator")
	opCtx := admin.WithPrincipal(ctx, operator)
	if _, err := s.JobCommand(opCtx, jobs.Command{Action: "run", AgentID: id, Kind: "shell"}, now); !errors.Is(err, jobs.ErrInvalid) {
		t.Fatal("arbitrary command", err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER no_audit BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.JobCommand(opCtx, jobs.Command{Action: "run", AgentID: id, Kind: "inventory"}, now); err == nil {
		t.Fatal("accepted without audit")
	}
	runs, _ := s.Jobs(ctx, "", 0, 101)
	if len(runs) != 0 {
		t.Fatal("partial enqueue")
	}
	s.db.Exec("DROP TRIGGER no_audit")
	jobID, err := s.JobCommand(opCtx, jobs.Command{Action: "run", AgentID: id, Kind: "inventory"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.JobCommand(opCtx, jobs.Command{Action: "cancel", ID: jobID}, now); err != nil {
		t.Fatal(err)
	}
	if j, err := s.ClaimJob(ctx, id, hash, now); err != nil || j != nil {
		t.Fatal("claimed canceled job", j, err)
	}
	for range 20 {
		if _, err = s.JobCommand(opCtx, jobs.Command{Action: "run", AgentID: id, Kind: "inventory"}, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.JobCommand(opCtx, jobs.Command{Action: "run", AgentID: id, Kind: "inventory"}, now); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("unbounded backlog", err)
	}
	if err = s.AdvanceJobs(ctx, now.Add(25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	runs, _ = s.Jobs(ctx, id, 0, 101)
	if runs[0].State != "expired" {
		t.Fatal(runs[0])
	}
}

func TestSchedulePauseEditAndResumePreserveQueuedWork(t *testing.T) {
	ctx := context.Background()
	s, id, _ := jobFixture(t)
	now := time.Now().UTC()
	schedule, err := s.JobCommand(ctx, jobs.Command{Action: "schedule.create", AgentID: id, Kind: "inventory", FirstRunAt: now, IntervalSeconds: 60}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AdvanceJobs(ctx, now); err != nil {
		t.Fatal(err)
	}
	if _, err = s.JobCommand(ctx, jobs.Command{Action: "schedule.disable", ID: schedule}, now); err != nil {
		t.Fatal(err)
	}
	if _, err = s.JobCommand(ctx, jobs.Command{Action: "schedule.update", ID: schedule, Kind: "updates", RefreshMetadata: true, FirstRunAt: now.Add(time.Hour), IntervalSeconds: 3600}, now); err != nil {
		t.Fatal(err)
	}
	schedules, _ := s.JobSchedules(ctx, id, "", 101)
	runs, _ := s.Jobs(ctx, id, 0, 101)
	if len(schedules) != 1 || schedules[0].Enabled || schedules[0].Kind != "updates" || schedules[0].IntervalSeconds != 3600 || len(runs) != 1 || runs[0].Kind != "inventory" {
		t.Fatal("changed pending work or resumed implicitly", schedules, runs)
	}
	if _, err = s.JobCommand(ctx, jobs.Command{Action: "schedule.enable", ID: schedule}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	schedules, _ = s.JobSchedules(ctx, id, "", 101)
	if !schedules[0].Enabled || !schedules[0].NextRunAt.Equal(now.Add(time.Minute)) {
		t.Fatal(schedules)
	}
}

func TestJobsDoNotCrossAgentOwnership(t *testing.T) {
	ctx := context.Background()
	s, id, hash := jobFixture(t)
	assets, err := s.Assets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	otherHash := ingest.Hash([]byte(strings.Repeat("b", 64)))
	if err = s.RegisterAgent(ctx, "other-agent", assets[0].ID, otherHash); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	jobID, err := s.JobCommand(ctx, jobs.Command{Action: "run", AgentID: id, Kind: "inventory"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if j, err := s.ClaimJob(ctx, "other-agent", otherHash, now); err != nil || j != nil {
		t.Fatal("another agent claimed job", j, err)
	}
	if j, err := s.ClaimJob(ctx, id, hash, now); err != nil || j == nil {
		t.Fatal(j, err)
	}
	if err = s.FinishJob(ctx, "other-agent", otherHash, jobs.Result{JobID: jobID, Status: "failed", Code: "collection_failed"}, now); !errors.Is(err, jobs.ErrTerminal) {
		t.Fatal("another agent finished job", err)
	}
	runs, _ := s.Jobs(ctx, id, 0, 101)
	if runs[0].State != "running" {
		t.Fatal(runs)
	}
}

func TestVersionSevenJobMigrationPreservesAgentsAndUsers(t *testing.T) {
	ctx := context.Background()
	s, id, hash := jobFixture(t)
	password, err := admin.HashPassword("fixture-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AdminCommand(ctx, admin.Command{Action: "user.create", Username: "root", Role: "administrator", PasswordHash: password}); err != nil {
		t.Fatal(err)
	}
	var seq int
	var name, path string
	if err = s.db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("DROP TABLE agent_job_journal; DROP TABLE agent_jobs; DROP TABLE agent_schedules; PRAGMA user_version=7"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = reopened.AgentBinding(ctx, id, hash); err != nil {
		t.Fatal("agent lost", err)
	}
	user, err := reopened.AdminUser(ctx, "root")
	if err != nil || user.PasswordHash != password || user.Role != "administrator" {
		t.Fatal("user lost", err)
	}
	if _, err = reopened.JobCommand(admin.WithPrincipal(ctx, user), jobs.Command{Action: "run", AgentID: id, Kind: "inventory"}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}
