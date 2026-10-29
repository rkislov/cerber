// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/rulepolicy"
	"github.com/rkislov/cerber/internal/telemetry"
	"testing"
	"time"
)

const chainSID = "S-1-5-21-111-222-333-1001"
const chainGUID = "{11111111-2222-3333-4444-555555555555}"

func chainEvent(t *testing.T, s *Store, agent, asset string, at time.Time, code int, fields map[string]string) string {
	t.Helper()
	provider := "Microsoft-Windows-Security-Auditing"
	if code == 1102 {
		provider = "Microsoft-Windows-Eventlog"
	}
	p, _ := json.Marshal(map[string]any{"event_id": code, "time": at.Format(time.RFC3339Nano), "computer": agent + ".lab", "provider": provider, "fields": fields})
	raw := telemetry.Raw{ID: telemetry.ID(agent, asset, at.String(), fmt.Sprint(code)), Source: "windows:Security", Cursor: at.String(), ObservedAt: at, Data: p}
	b := telemetry.Batch{SchemaVersion: 1, ID: telemetry.ID("batch", raw.ID), AgentID: agent, Records: []telemetry.Raw{raw}}
	if _, e := s.Accept(context.Background(), agent, asset, b); e != nil {
		t.Fatal(e)
	}
	if e := s.Step(context.Background()); e != nil {
		t.Fatal(e)
	}
	return telemetry.ID(agent, raw.ID)
}
func chainFields() map[string]string {
	return map[string]string{"TargetUserName": "Alice", "TargetDomainName": "LAB", "TargetUserSid": chainSID, "TargetLogonId": "0x123", "LogonGuid": chainGUID, "LogonType": "3", "IpAddress": "192.0.2.50"}
}
func TestCrossHostPoliciesLivePreviewEvidenceAndGlobalSuppression(t *testing.T) {
	s := storageFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-5 * time.Minute)
	chainEvent(t, s, "host1", "asset1", at, 4624, chainFields())
	chainEvent(t, s, "host2", "asset2", at.Add(time.Minute), 4624, chainFields())
	last := chainEvent(t, s, "host3", "asset3", at.Add(2*time.Minute), 4624, chainFields())
	detections, e := s.ReadDetections(ctx, 0, 100)
	if e != nil {
		t.Fatal(e)
	}
	counts := map[string]int{}
	for _, d := range detections {
		counts[d.Rule]++
		if d.Chain == nil || d.Chain.Hosts < 2 || d.Policy.Revision != 1 {
			t.Fatal(d)
		}
		for _, step := range d.Chain.Steps {
			r, e := s.ReadRaw(ctx, step.EventID)
			if e != nil || r.AgentID != step.AgentID || r.AssetID != step.AssetID {
				t.Fatal("foreign evidence", r, e)
			}
		}
	}
	if counts["chain.domain_account_hosts"] != 1 || counts["chain.logon_guid_hosts"] != 1 {
		t.Fatal("missing rule or cross-host suppression failed", counts)
	}
	cfg := rulepolicy.Defaults()["chain.domain_account_hosts"]
	before := policyState(t, s)
	preview, e := s.PreviewRule(ctx, RulePreviewRequest{Rule: "chain.domain_account_hosts", Config: cfg, EventIDs: []string{last}}, nil, "")
	if e != nil || len(preview.Rows) != 1 || len(preview.Rows[0].Findings) != 1 {
		t.Fatal(preview, e)
	}
	if preview.Rows[0].Findings[0].Policy.Revision != 0 || policyState(t, s) != before {
		t.Fatal("preview wrote state")
	}
	cfg.ExcludeAgents = []string{"host1"}
	preview, e = s.PreviewRule(ctx, RulePreviewRequest{Rule: "chain.domain_account_hosts", Config: cfg, EventIDs: []string{last}}, nil, "")
	if e != nil || len(preview.Rows[0].Findings) != 0 {
		t.Fatal("excluded participant counted", preview, e)
	}
	chainEvent(t, s, "host3", "asset3", at.Add(3*time.Minute), 1102, map[string]string{"SubjectUserName": "Alice", "SubjectDomainName": "LAB", "SubjectUserSid": chainSID, "SubjectLogonId": "0x123"})
	detections, _ = s.ReadDetections(ctx, 0, 100)
	found := false
	for _, d := range detections {
		if d.Rule == "chain.remote_logon_audit_clear" {
			found = true
			if len(d.Chain.Links) < 2 || d.Chain.Links[len(d.Chain.Links)-1].Kind != "local_session" {
				t.Fatal(d)
			}
		}
	}
	if !found {
		t.Fatal("missing ordered chain", detections)
	}
	var legacyCount int
	if e = s.db.QueryRow("SELECT count(*) FROM correlation_policy_active").Scan(&legacyCount); e != nil || legacyCount != 10 {
		t.Fatal("legacy binary policy table incompatible", legacyCount, e)
	}
}

type perAgentGroups map[string][]string

func (f perAgentGroups) CorrelationAgentGroups(_ context.Context, id string) ([]string, error) {
	return f[id], nil
}
func TestCrossHostIdentityIsolationAndGroups(t *testing.T) {
	s := storageFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-5 * time.Minute)
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	s.SetRuleGroupSource(perAgentGroups{"host1": {id}, "host3": {id}})
	chainEvent(t, s, "host1", "asset1", at, 4624, chainFields())
	f := chainFields()
	f["TargetUserSid"] = "S-1-5-21-444-555-666-1001"
	chainEvent(t, s, "other", "asset0", at.Add(time.Second), 4624, f)
	chainEvent(t, s, "host2", "asset2", at.Add(time.Minute), 4624, chainFields())
	last := chainEvent(t, s, "host3", "asset3", at.Add(2*time.Minute), 4624, chainFields())
	cfg := rulepolicy.Defaults()["chain.domain_account_hosts"]
	cfg.GroupIDs = []string{id}
	cfg.Threshold = 2
	p, e := s.PreviewRule(ctx, RulePreviewRequest{Rule: "chain.domain_account_hosts", Config: cfg, EventIDs: []string{last}}, nil, "")
	if e != nil || len(p.Rows[0].Findings) != 1 || p.Rows[0].Findings[0].Chain.Hosts != 2 {
		t.Fatal(p, e)
	}
	for _, step := range p.Rows[0].Findings[0].Chain.Steps {
		if step.AgentID == "host2" || step.AgentID == "other" {
			t.Fatal("foreign identity/group", step)
		}
	}
	cfg.Threshold = 3
	p, e = s.PreviewRule(ctx, RulePreviewRequest{Rule: "chain.domain_account_hosts", Config: cfg, EventIDs: []string{last}}, nil, "")
	if e != nil || len(p.Rows[0].Findings) != 0 {
		t.Fatal(p, e)
	}
	// Matching local session identifiers on different hosts do not join different SIDs.
	cfg = rulepolicy.Defaults()["chain.remote_logon_audit_clear"]
	bad := chainEvent(t, s, "host3", "asset3", at.Add(3*time.Minute), 1102, map[string]string{"SubjectUserName": "Alice", "SubjectDomainName": "LAB", "SubjectUserSid": chainSID, "SubjectLogonId": "0x999"})
	p, e = s.PreviewRule(ctx, RulePreviewRequest{Rule: "chain.remote_logon_audit_clear", Config: cfg, EventIDs: []string{bad}}, nil, "")
	if e != nil || len(p.Rows[0].Findings) != 0 {
		t.Fatal("local session mismatch", p, e)
	}
}
func TestChainPolicyVersionsRestartAndCompatibility(t *testing.T) {
	s := storageFixture(t)
	ctx := context.Background()
	rule := "chain.ssh_key_hosts"
	cfg := rulepolicy.Defaults()[rule]
	cfg.Threshold = 2
	v, e := s.ChangeRulePolicy(ctx, rulepolicy.Change{Action: "save", Rule: rule, Config: cfg, ExpectedRevision: 1, Reason: "two approved hosts"}, "owner")
	if e != nil || v.Revision != 2 {
		t.Fatal(v, e)
	}
	_, e = s.ChangeRulePolicy(ctx, rulepolicy.Change{Action: "rollback", Rule: rule, ExpectedRevision: 2, TargetRevision: 1, Reason: "restore"}, "owner")
	if e != nil {
		t.Fatal(e)
	}
	path := s.path
	s.Close()
	again, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer again.Close()
	history, e := again.RulePolicyHistory(ctx, rule, 0)
	if e != nil || len(history) != 3 || history[0].RestoredFrom != 1 || history[1].Config.Threshold != 2 {
		t.Fatal(history, e)
	}
	policies, e := again.RulePolicies(ctx)
	if e != nil || len(policies) != 14 {
		t.Fatal(policies, e)
	}
	var native int
	if e = again.db.QueryRow("SELECT count(*) FROM correlation_policy_active").Scan(&native); e != nil || native != 10 {
		t.Fatal(native, e)
	}
}
func TestCrossHostWindowBoundaryAndImmutableHistory(t *testing.T) {
	s := storageFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Hour)
	first := chainEvent(t, s, "host1", "asset1", at, 4624, chainFields())
	_ = first
	edge := chainEvent(t, s, "host2", "asset2", at.Add(900*time.Second), 4624, chainFields())
	late := chainEvent(t, s, "host3", "asset3", at.Add(901*time.Second), 4624, chainFields())
	cfg := rulepolicy.Defaults()["chain.domain_account_hosts"]
	cfg.Threshold = 2
	r, e := s.PreviewRule(ctx, RulePreviewRequest{Rule: "chain.domain_account_hosts", Config: cfg, EventIDs: []string{edge}}, nil, "")
	if e != nil || len(r.Rows[0].Findings) != 1 {
		t.Fatal("inclusive boundary", r, e)
	}
	cfg.ExcludeAgents = []string{"host2"}
	r, e = s.PreviewRule(ctx, RulePreviewRequest{Rule: "chain.domain_account_hosts", Config: cfg, EventIDs: []string{late}}, nil, "")
	if e != nil || len(r.Rows[0].Findings) != 0 {
		t.Fatal("expired event counted", r, e)
	}
	// Later processing of a very late old event cannot change an earlier preview.
	chainEvent(t, s, "host4", "asset4", at.Add(time.Second), 4624, chainFields())
	cfg.ExcludeAgents = nil
	cfg.Threshold = 3
	r, e = s.PreviewRule(ctx, RulePreviewRequest{Rule: "chain.domain_account_hosts", Config: cfg, EventIDs: []string{edge}}, nil, "")
	if e != nil || len(r.Rows[0].Findings) != 0 {
		t.Fatal("future ingestion sequence used", r, e)
	}
}
