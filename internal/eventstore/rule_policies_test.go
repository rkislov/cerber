// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/integrations"
	"github.com/rkislov/cerber/internal/rulepolicy"
	"github.com/rkislov/cerber/internal/telemetry"
	"reflect"
	"strings"
	"testing"
	"time"
)

type policyGroupFixture struct {
	groups []string
	err    error
}

func (f policyGroupFixture) CorrelationAgentGroups(context.Context, string) ([]string, error) {
	return f.groups, f.err
}
func policyState(t *testing.T, s *Store) string {
	t.Helper()
	out := map[string]any{}
	for _, q := range []string{"SELECT count(*) FROM detections", "SELECT count(*) FROM correlation_policy_versions", "SELECT count(*) FROM correlation_chain_policy_versions", "SELECT count(*) FROM correlation_windows_policy_versions", "SELECT sum(position) FROM consumer_cursors", "SELECT count(*) FROM event_retention_audit", "SELECT count(*) FROM pipeline_health_notifications"} {
		var v sql.NullInt64
		if e := s.db.QueryRow(q).Scan(&v); e != nil {
			t.Fatal(e)
		}
		out[q] = v.Int64
	}
	p, _ := json.Marshal(out)
	return string(p)
}
func TestDraftPreviewNoSideEffectsAndMonotonicRollback(t *testing.T) {
	s := storageFixture(t)
	ctx := context.Background()
	cfg := rulepolicy.Defaults()["auth.repeated_failures"]
	cfg.Enabled = false
	v, e := s.ChangeRulePolicy(ctx, rulepolicy.Change{Action: "save", Rule: "auth.repeated_failures", ExpectedRevision: 1, Config: cfg, Reason: "Fixture disabled"}, "admin")
	if e != nil || v.Revision != 2 {
		t.Fatal(v, e)
	}
	b := batch(t, "agent", 0, "failure", "failure")
	if _, e = s.Accept(ctx, "agent", "asset", b); e != nil {
		t.Fatal(e)
	}
	if e = s.Step(ctx); e != nil {
		t.Fatal(e)
	}
	rows, e := s.ReadEvents(ctx, telemetry.Query{Limit: 100})
	if e != nil {
		t.Fatal(e)
	}
	ids := []string{}
	for _, n := range rows {
		ids = append(ids, n.ID)
	}
	cfg.Enabled = true
	cfg.Threshold = 2
	before := policyState(t, s)
	preview, e := s.PreviewRule(ctx, RulePreviewRequest{Rule: "auth.repeated_failures", Config: cfg, EventIDs: ids}, nil, "")
	if e != nil || !preview.DryRun {
		t.Fatal(preview, e)
	}
	found := 0
	for _, r := range preview.Rows {
		for _, d := range r.Findings {
			found++
			if d.Policy == nil || d.Policy.Revision != 0 || d.Policy.Config.Threshold != 2 {
				t.Fatal(d)
			}
		}
	}
	if found != 1 || policyState(t, s) != before {
		t.Fatal("preview wrote production state", preview, before, policyState(t, s))
	}
	v, e = s.ChangeRulePolicy(ctx, rulepolicy.Change{Action: "save", Rule: v.Rule, ExpectedRevision: 2, Config: cfg, Reason: "Fixture threshold"}, "admin")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Accept(ctx, "agent", "asset", batch(t, "agent", 2, "failure")); e != nil {
		t.Fatal(e)
	}
	if e = s.Step(ctx); e != nil {
		t.Fatal(e)
	}
	detections, _ := s.ReadDetections(ctx, 0, 100)
	if len(detections) != 1 || detections[0].Policy.Revision != 3 {
		t.Fatal(detections)
	}
	snapshot := *detections[0].Policy
	restored, e := s.ChangeRulePolicy(ctx, rulepolicy.Change{Action: "rollback", Rule: v.Rule, ExpectedRevision: 3, TargetRevision: 1, Reason: "Restore original"}, "second-admin")
	if e != nil || restored.Revision != 4 || restored.RestoredFrom != 1 || restored.Config.Threshold != 5 {
		t.Fatal(restored, e)
	}
	if _, e = s.ChangeRulePolicy(ctx, rulepolicy.Change{Action: "save", Rule: v.Rule, ExpectedRevision: 3, Config: cfg, Reason: "Stale"}, "admin"); !errors.Is(e, rulepolicy.ErrConflict) {
		t.Fatal(e)
	}
	detections, _ = s.ReadDetections(ctx, 0, 100)
	if !reflect.DeepEqual(snapshot, *detections[0].Policy) {
		t.Fatal("historical explanation changed")
	}
	history, e := s.RulePolicyHistory(ctx, v.Rule, 0)
	if e != nil || len(history) != 4 || history[3].Revision != 1 {
		t.Fatal(history, e)
	}
}
func TestGroupAndExclusionsAffectLiveAndDraftIdentically(t *testing.T) {
	for _, test := range []struct {
		name    string
		groups  []string
		exclude bool
		want    int
	}{{"member", []string{strings.Repeat("a", 32)}, false, 1}, {"outside", nil, false, 0}, {"excluded", []string{strings.Repeat("a", 32)}, true, 0}} {
		t.Run(test.name, func(t *testing.T) {
			s := storageFixture(t)
			ctx := context.Background()
			s.SetRuleGroupSource(policyGroupFixture{groups: test.groups})
			cfg := rulepolicy.Defaults()["auth.repeated_failures"]
			cfg.GroupIDs = []string{strings.Repeat("a", 32)}
			cfg.Threshold = 2
			if test.exclude {
				cfg.ExcludeSourceCIDRs = []string{"10.1.2.0/24"}
			}
			if _, e := s.ChangeRulePolicy(ctx, rulepolicy.Change{Action: "save", Rule: "auth.repeated_failures", ExpectedRevision: 1, Config: cfg, Reason: "Fixture scope"}, "admin"); e != nil {
				t.Fatal(e)
			}
			if _, e := s.Accept(ctx, "agent", "asset", batch(t, "agent", 0, "failure", "failure")); e != nil {
				t.Fatal(e)
			}
			if e := s.Step(ctx); e != nil {
				t.Fatal(e)
			}
			d, _ := s.ReadDetections(ctx, 0, 100)
			if len(d) != test.want {
				t.Fatal(d)
			}
			rows, _ := s.ReadEvents(ctx, telemetry.Query{Limit: 100})
			ids := []string{}
			for _, n := range rows {
				ids = append(ids, n.ID)
			}
			r, e := s.PreviewRule(ctx, RulePreviewRequest{Rule: "auth.repeated_failures", Config: cfg, EventIDs: ids}, nil, "")
			if e != nil {
				t.Fatal(e)
			}
			got := 0
			for _, row := range r.Rows {
				got += len(row.Findings)
			}
			if got != test.want {
				t.Fatal(r)
			}
		})
	}
}
func TestGroupLookupFailureRetainsCorrelationCursor(t *testing.T) {
	s := storageFixture(t)
	ctx := context.Background()
	cfg := rulepolicy.Defaults()["auth.repeated_failures"]
	cfg.GroupIDs = []string{strings.Repeat("a", 32)}
	s.SetRuleGroupSource(policyGroupFixture{err: errors.New("control unavailable")})
	s.ChangeRulePolicy(ctx, rulepolicy.Change{Action: "save", Rule: "auth.repeated_failures", ExpectedRevision: 1, Config: cfg, Reason: "Fixture"}, "admin")
	s.Accept(ctx, "agent", "asset", batch(t, "agent", 0, "failure"))
	if e := s.Step(ctx); e == nil {
		t.Fatal("failed group lookup acknowledged")
	}
	var cursor int
	s.db.QueryRow("SELECT position FROM consumer_cursors WHERE name='correlator/1'").Scan(&cursor)
	if cursor != 0 {
		t.Fatal(cursor)
	}
}
func TestIOCRulePoliciesAndPreviewDoNotNotify(t *testing.T) {
	s := storageFixture(t)
	ctx := context.Background()
	cfg := rulepolicy.Defaults()["threatfox.ioc_match"]
	cfg.Enabled = false
	s.ChangeRulePolicy(ctx, rulepolicy.Change{Action: "save", Rule: "threatfox.ioc_match", ExpectedRevision: 1, Config: cfg, Reason: "Fixture disabled"}, "admin")
	s.Accept(ctx, "agent", "asset", batch(t, "agent", 0, "failure"))
	if e := s.Step(ctx); e != nil {
		t.Fatal(e)
	}
	index := integrations.NewIndex([]integrations.IOC{{ID: "fixture", Type: "ip", Value: "10.1.2.3", First: time.Now().Add(-time.Hour), Last: time.Now()}})
	if e := s.ScanIOC(ctx, index, "fixture-revision"); e != nil {
		t.Fatal(e)
	}
	rows, _ := s.ReadEvents(ctx, telemetry.Query{Limit: 100})
	cfg.Enabled = true
	before := policyState(t, s)
	r, e := s.PreviewRule(ctx, RulePreviewRequest{Rule: "threatfox.ioc_match", Config: cfg, EventIDs: []string{rows[0].ID}}, index, "fixture-revision")
	if e != nil || len(r.Rows[0].Findings) != 1 || policyState(t, s) != before {
		t.Fatal(r, e)
	}
	notifications, e := s.NotificationBatch(ctx, 0)
	if e != nil || len(notifications) != 0 {
		t.Fatal(notifications, e)
	}
}

func TestPreviewUsesConfiguredEventTimeWindow(t *testing.T) {
	s := storageFixture(t)
	ctx := context.Background()
	b := batch(t, "agent", 0, "failure", "failure", "failure")
	base := time.Now().UTC().Add(-2 * time.Minute)
	for i, seconds := range []int{0, 30, 90} {
		var p map[string]any
		json.Unmarshal(b.Records[i].Data, &p)
		p["time"] = base.Add(time.Duration(seconds) * time.Second).Format(time.RFC3339Nano)
		b.Records[i].Data, _ = json.Marshal(p)
	}
	if _, e := s.Accept(ctx, "agent", "asset", b); e != nil {
		t.Fatal(e)
	}
	if e := s.Step(ctx); e != nil {
		t.Fatal(e)
	}
	rows, _ := s.ReadEvents(ctx, telemetry.Query{Limit: 100})
	ids := []string{}
	for _, n := range rows {
		ids = append(ids, n.ID)
	}
	cfg := rulepolicy.Defaults()["auth.repeated_failures"]
	cfg.Threshold = 3
	cfg.WindowSeconds = 60
	r, e := s.PreviewRule(ctx, RulePreviewRequest{Rule: "auth.repeated_failures", Config: cfg, EventIDs: ids}, nil, "")
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range r.Rows {
		if len(row.Findings) > 0 {
			t.Fatal("event outside configured window counted", r)
		}
	}
	cfg.WindowSeconds = 120
	r, e = s.PreviewRule(ctx, RulePreviewRequest{Rule: "auth.repeated_failures", Config: cfg, EventIDs: ids}, nil, "")
	if e != nil || len(r.Rows[2].Findings) != 1 {
		t.Fatal(r, e)
	}
}
