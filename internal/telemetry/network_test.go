// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCEFNormalization(t *testing.T) {
	now := time.Now().UTC()
	base := "CEF:0|FESS|WAF|2|block|WAF event|5|src=::ffff:192.0.2.3 dvchost=app.example request=GET /login?x\\=1 rt=" + now.Format(time.RFC3339Nano)
	for _, v := range []struct {
		line, profile string
		valid         bool
	}{{base, "fess", true}, {"<134>1 2026-01-01T00:00:00Z fence-siem - - - - " + base, "fess", true}, {base + " src=192.0.2.4", "fess", false}, {base + "\nforged", "fess", false}, {base, "invented", false}, {"CEF:0|broken", "firewall", false}} {
		data, _ := json.Marshal(map[string]string{"line": v.line, "profile": v.profile})
		n := Normalize(RawRecord{Sequence: 1, AgentID: "agent", ReceivedAt: now, Raw: Raw{ID: ID(v.line), Source: "network:cef", Data: data}})
		if (n.Status == "parsed") != v.valid {
			t.Fatalf("%s: %+v", v.line, n)
		}
		if v.valid && (n.SourceIP != "192.0.2.3" || n.Action != "deny" || n.Request != "GET /login?x=1") {
			t.Fatalf("fields %+v", n)
		}
	}
}

func TestFEssAuditHasActorWithoutSourceIP(t *testing.T) {
	now := time.Now().UTC()
	data, _ := json.Marshal(map[string]string{"profile": "fess", "line": "CEF:0|Fence|WAF|1|update|Audit|4|suser=admin cs1=policy rt=" + now.Format(time.RFC3339Nano)})
	n := Normalize(RawRecord{ReceivedAt: now, Raw: Raw{Source: "network:cef", Data: data}})
	if n.Status != "parsed" || n.Class != "audit" || n.User != "admin" || n.Action != "configuration_change" {
		t.Fatal(n)
	}
}
