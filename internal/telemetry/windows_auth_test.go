// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"encoding/json"
	"testing"
	"time"
)

func flowNormalize(t *testing.T, code int, f map[string]string) Normalized {
	t.Helper()
	now := time.Now().UTC()
	p, _ := json.Marshal(map[string]any{"event_id": code, "provider": "Microsoft-Windows-Security-Auditing", "computer": "source.lab", "time": now.Format(time.RFC3339Nano), "fields": f})
	return Normalize(RawRecord{AgentID: "agent", AssetID: "asset", ReceivedAt: now, Raw: Raw{ID: ID("flow"), Source: "windows:Security", ObservedAt: now, Data: p}})
}
func TestWindowsCredentialAndTicketRolesRemainSeparate(t *testing.T) {
	a := "S-1-5-21-1-2-3-1001"
	g := "{11111111-2222-3333-4444-555555555555}"
	n := flowNormalize(t, 4648, map[string]string{"SubjectUserName": "Alice", "SubjectDomainName": "LAB", "SubjectUserSid": a, "SubjectLogonId": "0x111", "LogonGuid": g, "TargetUserName": "Bob", "TargetDomainName": "LAB", "TargetLogonGuid": "{22222222-2222-3333-4444-555555555555}", "TargetServerName": "files.lab", "ProcessName": "C:\\Windows\\runas.exe"})
	if n.Class != "credentials" || n.Outcome != "unknown" || n.User != `lab\alice` || n.Identity.AccountSID != a || n.WindowsAuth.AccountRef != `lab\bob` || n.WindowsAuth.TargetGUID == n.Identity.SessionGUID {
		t.Fatal(n)
	}
	f := map[string]string{"TargetUserName": "Bob@LAB", "TargetDomainName": "LAB", "ServiceName": "files$", "ServiceSid": "S-1-5-21-1-2-3-2000", "LogonGuid": g, "Status": "0x0", "IpAddress": "::ffff:192.0.2.5"}
	n = flowNormalize(t, 4769, f)
	if n.Class != "kerberos" || n.Outcome != "success" || n.Identity.AccountSID != "" || n.Identity.AccountKey != "" || n.WindowsAuth.AccountRef != `lab\bob` || n.WindowsAuth.ServiceSID != f["ServiceSid"] || n.SourceIP != "192.0.2.5" {
		t.Fatal(n)
	}
	for status, want := range map[string]string{"0x18": "failure", "": "unknown", "garbage": "unknown"} {
		f["Status"] = status
		n = flowNormalize(t, 4769, f)
		if n.Outcome != want {
			t.Fatal(status, n)
		}
	}
}
func TestWindowsQualifiedNameDoesNotGuessAliases(t *testing.T) {
	for _, v := range []struct{ name, realm string }{{"alice@corp.example", "CORP"}, {"alice", "workgroup"}, {"host$@lab", "lab"}, {"LAB\\alice", "LAB"}, {"alice", "source"}} {
		if WindowsAccountRef(v.name, v.realm, "source.lab") != "" {
			t.Fatal(v)
		}
	}
	if WindowsAccountRef("ALICE@corp.example", "CORP.EXAMPLE", "source.lab") != `corp.example\alice` {
		t.Fatal("UPN normalization")
	}
}
