// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"github.com/rkislov/cerber/internal/telemetry"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPipelineHealthAlertsRecoveryAndQuota(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, filepath.Join(t.TempDir(), "health.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Now().UTC()
	b := journalBatch("agent", 0, 2, now.Add(-time.Hour))
	if _, e = s.Accept(ctx, b.AgentID, "asset", b); e != nil {
		t.Fatal(e)
	}
	s.db.Exec("UPDATE raw_events SET received_at=?", stamp(now.Add(-time.Hour)))
	s.db.Exec("UPDATE journal_usage SET raw_bytes=?", 900<<20)
	if e = s.SamplePipelineHealth(ctx, now); e != nil {
		t.Fatal(e)
	}
	v, e := s.PipelineHealth(ctx)
	if e != nil || len(v.Alerts) != 2 || v.PendingNormalization != 2 {
		t.Fatal(v, e)
	}
	notices, _ := s.HealthNotificationBatch(ctx, 0)
	if len(notices) != 2 {
		t.Fatal(notices)
	}
	for _, n := range notices {
		if n.Details.Kind != "health" || n.Details.Severity == "" {
			t.Fatal("missing health mail context", n.Details)
		}
	}
	if e = s.SamplePipelineHealth(ctx, now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	again, _ := s.HealthNotificationBatch(ctx, 0)
	if len(again) != 2 {
		t.Fatal("duplicate mail", again)
	}
	policy := v.Retention.Policy
	policy.MaxBytes = 2 << 30
	if e = s.SetRetention(ctx, policy, "admin", now); e != nil {
		t.Fatal(e)
	}
	if e = s.Step(ctx); e != nil {
		t.Fatal(e)
	}
	if e = s.SamplePipelineHealth(ctx, now.Add(30*time.Second)); e != nil {
		t.Fatal(e)
	}
	v, _ = s.PipelineHealth(ctx)
	if len(v.Alerts) != 0 || v.PendingCorrelation != 0 || v.ProcessedPerSecond <= 0 {
		t.Fatal(v)
	}
	notices, _ = s.HealthNotificationBatch(ctx, 0)
	if len(notices) != 4 {
		t.Fatal("recovery notification missing", notices)
	}
	for _, n := range notices[2:] {
		if n.Details.Kind != "recovery" {
			t.Fatal("recovery mail incorrectly classified", n.Details)
		}
	}
	policy = v.Retention.Policy
	policy.MaxBytes = 0
	if e = s.SetRetention(ctx, policy, "old-client", now); e != nil {
		t.Fatal(e)
	}
	r, _ := s.RetentionStatus(ctx)
	if r.Policy.MaxBytes != 2<<30 {
		t.Fatal("old client reset quota")
	}
}
func TestVerifiedArchiveRecoveryAndTamper(t *testing.T) {
	s, dir, _ := oldJournal(t)
	ctx := context.Background()
	if _, e := s.MaintainRequested(ctx, "admin", time.Now()); e != nil {
		t.Fatal(e)
	}
	list, e := s.Archives(ctx, 0)
	if e != nil || len(list) != 1 {
		t.Fatal(list, e)
	}
	v, e := s.VerifyArchive(ctx, list[0].ID)
	if e != nil || !v.Verified || len(v.EventIDs) != 2 {
		t.Fatal(v, e)
	}
	for _, id := range v.EventIDs {
		r, e := s.ReadRaw(ctx, id)
		if e != nil || !r.Archived || r.ArchiveID != list[0].ID {
			t.Fatal(r, e)
		}
	}
	p := filepath.Join(dir, list[0].ID+".jsonl.gz")
	data, _ := os.ReadFile(p)
	data[len(data)/2] ^= 1
	os.WriteFile(p, data, 0600)
	if _, e = s.VerifyArchive(ctx, list[0].ID); e == nil {
		t.Fatal("corrupt archive verified")
	}
}
func TestRetentionQuotaValidation(t *testing.T) {
	for _, n := range []int64{-1, 1, 63 << 20, 2 << 40} {
		p := telemetry.RetentionPolicy{HotDays: 7, ArchiveDays: 0, Version: 1, MaxBytes: n}
		if p.Validate() == nil {
			t.Fatal(n)
		}
	}
}
