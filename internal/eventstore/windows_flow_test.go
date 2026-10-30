// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"github.com/rkislov/cerber/internal/incidents"
	"github.com/rkislov/cerber/internal/rulepolicy"
	"github.com/rkislov/cerber/internal/telemetry"
	"testing"
	"time"
)

const actorGUID = "{11111111-1111-1111-1111-111111111111}"
const targetGUID = "{22222222-2222-2222-2222-222222222222}"

func actorFields() map[string]string {
	return map[string]string{"TargetUserName": "Alice", "TargetDomainName": "LAB", "TargetUserSid": chainSID, "TargetLogonId": "0x111", "LogonGuid": actorGUID, "LogonType": "2", "IpAddress": "192.0.2.5"}
}
func explicitFields() map[string]string {
	return map[string]string{"SubjectUserName": "Alice", "SubjectDomainName": "LAB", "SubjectUserSid": chainSID, "SubjectLogonId": "0x111", "LogonGuid": actorGUID, "TargetUserName": "Bob", "TargetDomainName": "LAB", "TargetLogonGuid": targetGUID, "TargetServerName": "files.lab", "ProcessName": "C:\\Windows\\System32\\runas.exe", "ProcessId": "0x123", "IpAddress": "192.0.2.5"}
}
func ticketFields() map[string]string {
	return map[string]string{"TargetUserName": "Bob@LAB", "TargetDomainName": "LAB", "ServiceName": "files$", "ServiceSid": "S-1-5-21-111-222-333-2000", "LogonGuid": targetGUID, "Status": "0x0", "TicketEncryptionType": "0x12", "IpAddress": "192.0.2.5"}
}
func targetFields() map[string]string {
	return map[string]string{"TargetUserName": "Bob", "TargetDomainName": "LAB", "TargetUserSid": "S-1-5-21-111-222-333-1002", "TargetLogonId": "0x222", "LogonGuid": targetGUID, "LogonType": "3", "IpAddress": "192.0.2.5"}
}
func TestWindowsFlowLivePreviewAndIncidentGraph(t *testing.T) {
	s := storageFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-5 * time.Minute)
	chainEvent(t, s, "workstation", "source", at, 4624, actorFields())
	chainEvent(t, s, "workstation", "source", at.Add(time.Minute), 4648, explicitFields())
	chainEvent(t, s, "dc", "dc-asset", at.Add(2*time.Minute), 4769, ticketFields())
	last := chainEvent(t, s, "files", "files-asset", at.Add(3*time.Minute), 4624, targetFields())
	ds, e := s.ReadDetections(ctx, 0, 100)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, d := range ds {
		if d.Rule != "chain.kerberos_logon" && d.Rule != "chain.explicit_credentials_logon" {
			t.Fatal("new records polluted native rules", d.Rule)
		}
		count++
		if d.Chain.Version != 2 || d.Chain.Hosts != 3 || len(d.Chain.Steps) != 4 || len(d.Chain.Links) != 3 {
			t.Fatal(d)
		}
		if d.Chain.Steps[0].Identity.AccountSID != chainSID || d.Chain.Steps[1].User != `lab\alice` || d.Chain.Steps[1].WindowsAuth.AccountRef != `lab\bob` || d.Chain.Steps[2].Identity.AccountSID != "" {
			t.Fatal("roles conflated", d.Chain)
		}
		before := policyState(t, s)
		r, e := s.PreviewRule(ctx, RulePreviewRequest{Rule: d.Rule, Config: rulepolicy.Defaults()[d.Rule], EventIDs: []string{last}}, nil, "")
		if e != nil || len(r.Rows[0].Findings) != 1 || len(r.Rows[0].Findings[0].Chain.Steps) != 4 || r.Rows[0].Findings[0].Policy.Revision != 0 || policyState(t, s) != before {
			t.Fatal(r, e)
		}
	}
	if count != 2 {
		t.Fatal(ds)
	}
	card, e := s.IncidentCommand(ctx, incidents.Command{Action: "create", Title: "Windows flow", Severity: "medium", DetectionID: ds[0].ID}, "owner", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	graph, e := s.IncidentGraph(ctx, card.ID)
	if e != nil || len(graph.Anchors) != 1 || graph.Anchors[0].Chain.Version != 2 {
		t.Fatal(graph, e)
	}
	for _, class := range []string{"kerberos", "credentials"} {
		items, e := s.ReadEvents(ctx, telemetry.Query{Class: class, Limit: 10})
		if e != nil || len(items) != 1 {
			t.Fatal(class, items, e)
		}
	}
	var native, chains int
	s.db.QueryRow("SELECT count(*) FROM correlation_policy_active").Scan(&native)
	s.db.QueryRow("SELECT count(*) FROM correlation_chain_policy_active").Scan(&chains)
	if native != 10 || chains != 4 {
		t.Fatal("older binary policy counts changed", native, chains)
	}
}
func TestWindowsFlowRejectsWrongGUIDNamesFailuresAndFutureDelivery(t *testing.T) {
	for _, test := range []struct {
		name, rule string
		modify     func(map[string]string)
	}{
		{"failed_ticket", "chain.kerberos_logon", func(f map[string]string) { f["Status"] = "0x18" }},
		{"missing_status", "chain.kerberos_logon", func(f map[string]string) { delete(f, "Status") }},
		{"wrong_realm", "chain.kerberos_logon", func(f map[string]string) { f["TargetDomainName"] = "OTHER"; f["TargetUserName"] = "Bob@OTHER" }},
		{"wrong_name", "chain.kerberos_logon", func(f map[string]string) { f["TargetUserName"] = "Alice@LAB" }},
		{"subject_guid_is_not_target", "chain.explicit_credentials_logon", func(f map[string]string) {
			f["LogonGuid"] = targetGUID
			f["TargetLogonGuid"] = "{00000000-0000-0000-0000-000000000000}"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := storageFixture(t)
			ctx := context.Background()
			at := time.Now().UTC().Add(-5 * time.Minute)
			code := 4769
			f := ticketFields()
			if test.rule == "chain.explicit_credentials_logon" {
				code = 4648
				f = explicitFields()
			}
			test.modify(f)
			chainEvent(t, s, "source", "source-asset", at, code, f)
			last := chainEvent(t, s, "files", "files-asset", at.Add(time.Minute), 4624, targetFields())
			r, e := s.PreviewRule(ctx, RulePreviewRequest{Rule: test.rule, Config: rulepolicy.Defaults()[test.rule], EventIDs: []string{last}}, nil, "")
			if e != nil || len(r.Rows[0].Findings) != 0 {
				t.Fatal(r, e)
			}
		})
	}
	s := storageFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-5 * time.Minute)
	last := chainEvent(t, s, "files", "files-asset", at.Add(time.Minute), 4624, targetFields())
	chainEvent(t, s, "dc", "dc-asset", at, 4769, ticketFields())
	r, e := s.PreviewRule(ctx, RulePreviewRequest{Rule: "chain.kerberos_logon", Config: rulepolicy.Defaults()["chain.kerberos_logon"], EventIDs: []string{last}}, nil, "")
	if e != nil || len(r.Rows[0].Findings) != 0 {
		t.Fatal("late ticket replayed old logon", r, e)
	}
}
func TestWindowsFlowGroupsWindowAndOwnPolicyHistory(t *testing.T) {
	s := storageFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-20 * time.Minute)
	g := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	s.SetRuleGroupSource(perAgentGroups{"workstation": {g}, "files": {g}})
	chainEvent(t, s, "workstation", "source", at, 4624, actorFields())
	chainEvent(t, s, "workstation", "source", at.Add(time.Minute), 4648, explicitFields())
	chainEvent(t, s, "dc", "dc-asset", at.Add(2*time.Minute), 4769, ticketFields())
	last := chainEvent(t, s, "files", "files-asset", at.Add(3*time.Minute), 4624, targetFields())
	cfg := rulepolicy.Defaults()["chain.kerberos_logon"]
	cfg.GroupIDs = []string{g}
	r, e := s.PreviewRule(ctx, RulePreviewRequest{Rule: "chain.kerberos_logon", Config: cfg, EventIDs: []string{last}}, nil, "")
	if e != nil || len(r.Rows[0].Findings) != 0 {
		t.Fatal("excluded DC joined", r, e)
	}
	cfg = rulepolicy.Defaults()["chain.explicit_credentials_logon"]
	cfg.GroupIDs = []string{g}
	r, e = s.PreviewRule(ctx, RulePreviewRequest{Rule: "chain.explicit_credentials_logon", Config: cfg, EventIDs: []string{last}}, nil, "")
	if e != nil || len(r.Rows[0].Findings) != 1 || len(r.Rows[0].Findings[0].Chain.Steps) != 3 {
		t.Fatal(r, e)
	}
	cfg.GroupIDs = nil
	cfg.WindowSeconds = 10
	r, e = s.PreviewRule(ctx, RulePreviewRequest{Rule: "chain.explicit_credentials_logon", Config: cfg, EventIDs: []string{last}}, nil, "")
	if e != nil || len(r.Rows[0].Findings) != 0 {
		t.Fatal("outside window", r, e)
	}
	cfg = rulepolicy.Defaults()["chain.explicit_credentials_logon"]
	cfg.Enabled = false
	v, e := s.ChangeRulePolicy(ctx, rulepolicy.Change{Action: "save", Rule: "chain.explicit_credentials_logon", Config: cfg, ExpectedRevision: 1, Reason: "fixture disable"}, "owner")
	if e != nil || v.Revision != 2 {
		t.Fatal(v, e)
	}
	v, e = s.ChangeRulePolicy(ctx, rulepolicy.Change{Action: "rollback", Rule: v.Rule, ExpectedRevision: 2, TargetRevision: 1, Reason: "restore Windows-flow"}, "owner")
	if e != nil || v.Revision != 3 || !v.Config.Enabled {
		t.Fatal(v, e)
	}
	cfg.Threshold = 4
	if _, e = rulepolicy.Canonical(v.Rule, cfg); e == nil {
		t.Fatal("impossible host threshold accepted")
	}
}
