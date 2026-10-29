// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNormalizeSourceIdentityAndQuarantine(t *testing.T) {
	now := time.Now().UTC()
	p, _ := json.Marshal(map[string]string{"__REALTIME_TIMESTAMP": "1700000000000000", "SYSLOG_IDENTIFIER": "sshd", "_UID": "0", "_EXE": "/usr/sbin/sshd", "MESSAGE": "Failed password for invalid user Alice from ::ffff:192.0.2.1 port 22 ssh2"})
	r := RawRecord{Sequence: 1, AgentID: ID("a"), AssetID: "server-asset", ReceivedAt: now, Raw: Raw{ID: ID("r"), Source: "journald", ObservedAt: now, Data: p}}
	n := Normalize(r)
	if n.Class != "authentication" || n.Outcome != "failure" || n.User != "alice" || n.SourceIP != "192.0.2.1" {
		t.Fatal(n)
	}
	var v map[string]string
	json.Unmarshal(p, &v)
	v["_UID"] = "1000"
	r.Raw.Data, _ = json.Marshal(v)
	n = Normalize(r)
	if n.Class == "authentication" {
		t.Fatal("message spoofed sshd")
	}
	r.Raw.Data = json.RawMessage(`{"MESSAGE":[1,2]}`)
	n = Normalize(r)
	if n.Status != "quarantine" {
		t.Fatal(n)
	}
}

func TestExtremeTimestampDoesNotPoisonPipeline(t *testing.T) {
	now := time.Now().UTC()
	n := Normalize(RawRecord{ReceivedAt: now, Raw: Raw{Source: "journald", ObservedAt: now, Data: json.RawMessage(`{"__REALTIME_TIMESTAMP":"9223372036854775807","MESSAGE":"future"}`)}})
	if n.Status != "quarantine" || !n.EventTime.Equal(now) {
		t.Fatal(n)
	}
	if _, e := json.Marshal(n); e != nil {
		t.Fatal(e)
	}
}

func TestWindowsAuditClearedUsesEventlogSubjectIdentity(t *testing.T) {
	now := time.Now().UTC()
	raw := RawRecord{AgentID: ID("agent"), AssetID: "asset", ReceivedAt: now, Raw: Raw{ID: ID("audit"), Source: "windows:Security", ObservedAt: now}}
	p := map[string]any{"event_id": 1102, "time": now.Format(time.RFC3339Nano), "provider": "Microsoft-Windows-Eventlog", "fields": map[string]string{"SubjectUserName": "Alice", "SubjectDomainName": "LAB"}}
	raw.Raw.Data, _ = json.Marshal(p)
	n := Normalize(raw)
	if n.Class != "audit" || n.Action != "log_cleared" || n.User != `lab\alice` || n.Parser != "windows-audit/3" {
		t.Fatal(n)
	}
	p["provider"] = "Unknown-Application"
	raw.Raw.Data, _ = json.Marshal(p)
	if n = Normalize(raw); n.Class == "audit" {
		t.Fatal("untrusted provider became audit clearing", n)
	}
	p["provider"] = "Microsoft-Windows-Eventlog"
	p["event_id"] = 4624
	raw.Raw.Data, _ = json.Marshal(p)
	if n = Normalize(raw); n.Class == "authentication" {
		t.Fatal("Eventlog logon provider spoofed", n)
	}
}
