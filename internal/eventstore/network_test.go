// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/telemetry"
	"path/filepath"
	"testing"
	"time"
)

func TestNetworkRulesIsolationReplayAndEvidence(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, filepath.Join(t.TempDir(), "events.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	agent := "network-agent"
	now := time.Now().UTC().Add(-time.Minute)
	serial := 0
	send := func(profile, act, host string, count int) {
		t.Helper()
		b := telemetry.Batch{SchemaVersion: 1, AgentID: agent, ID: telemetry.ID(fmt.Sprint(serial), act, host)}
		for i := 0; i < count; i++ {
			serial++
			name := "Firewall event"
			sig := "traffic"
			if profile == "fess" {
				name = "WAF event"
				sig = act
				if act == "proxied" {
					name = "Proxy access"
				}
			}
			line := fmt.Sprintf("CEF:0|Vendor|Product|1|%s|%s|5|act=%s src=192.0.2.2 dst=192.0.2.10 dpt=%d dvchost=%s rt=%s", sig, name, act, 1000+i, host, now.Format(time.RFC3339Nano))
			data, _ := json.Marshal(map[string]string{"line": line, "profile": profile})
			c := fmt.Sprint(serial)
			b.Records = append(b.Records, telemetry.Raw{ID: telemetry.ID(c), Source: "network:cef", Cursor: c, ObservedAt: now, Data: data})
		}
		if _, e := s.Accept(ctx, agent, "network-asset", b); e != nil {
			t.Fatal(e)
		}
		if e = s.Step(ctx); e != nil {
			t.Fatal(e)
		}
		if e = s.Step(ctx); e != nil {
			t.Fatal(e)
		}
	}
	send("firewall", "deny", "fw-a", 20)
	send("firewall", "deny", "fw-a", 20) // suppressed
	send("firewall", "deny", "fw-b", 20) // separate appliance
	send("fess", "block", "app-a", 10)
	send("fess", "proxied", "app-b", 1) // isolated virtual host
	send("fess", "proxied", "app-a", 1)
	ds, e := s.ReadDetections(ctx, 0, 100)
	if e != nil || len(ds) != 4 {
		t.Fatalf("detections %d: %+v %v", len(ds), ds, e)
	}
	counts := map[string]int{}
	for _, d := range ds {
		counts[d.Rule]++
		for _, id := range d.Evidence {
			if _, e := s.ReadRaw(ctx, id); e != nil {
				t.Fatal(e)
			}
		}
	}
	if counts["firewall.port_scan"] != 2 || counts["fess.blocked_burst"] != 1 || counts["fess.allowed_after_blocks"] != 1 {
		t.Fatal(counts)
	}
}
