// SPDX-License-Identifier: Apache-2.0
package correlation

import (
	"github.com/rkislov/cerber/internal/telemetry"
	"testing"
	"time"
)

func investigationPair() (telemetry.Detection, telemetry.Detection) {
	at := time.Now()
	a := telemetry.Detection{ID: telemetry.ID("a"), Version: 1, AgentID: "agent", AssetID: "asset", User: "LAB\\Alice", SourceIP: "192.0.2.1", LastSeen: at, Evidence: []string{telemetry.ID("raw")}, Rule: "auth.success_after_failures"}
	b := a
	b.ID = telemetry.ID("b")
	b.LastSeen = at.Add(time.Minute)
	b.Rule = "windows.audit_log_cleared"
	return a, b
}
func TestDirectInvestigationIdentityAndTime(t *testing.T) {
	a, b := investigationPair()
	r, k := RelatedReasons(a, b)
	if len(r) != 3 || len(k) != 3 {
		t.Fatal(r, k)
	}
	for _, change := range []func(*telemetry.Detection){func(d *telemetry.Detection) { d.AgentID = "other" }, func(d *telemetry.Detection) { d.AssetID = "other" }, func(d *telemetry.Detection) { d.LastSeen = a.LastSeen.Add(InvestigationWindow + time.Nanosecond) }} {
		x := b
		change(&x)
		if _, k := RelatedReasons(a, x); len(k) > 0 {
			t.Fatal(k)
		}
	}
	b.LastSeen = a.LastSeen.Add(InvestigationWindow)
	if _, k := RelatedReasons(a, b); len(k) == 0 {
		t.Fatal("inclusive boundary lost")
	}
	b.Evidence = nil
	b.User = "LAB\\alice"
	b.SourceIP = "198.51.100.1"
	if _, k := RelatedReasons(a, b); len(k) > 0 {
		t.Fatal("case-sensitive identity broadened", k)
	}
	b.SourceIP = "::ffff:192.0.2.1"
	if _, k := RelatedReasons(a, b); len(k) != 1 || k[0] != "same_remote_ip" {
		t.Fatal(k)
	}
	a.SourceIP = "127.0.0.1"
	b.SourceIP = a.SourceIP
	if _, k := RelatedReasons(a, b); len(k) > 0 {
		t.Fatal("loopback joined unrelated senders", k)
	}
}
func TestInvestigationHypothesesDoNotInferCausalityFromIP(t *testing.T) {
	a, b := investigationPair()
	if h := InvestigationHypotheses([]telemetry.Detection{b, a}); len(h) != 1 || h[0].Rule != "investigation.auth_then_audit_clear" {
		t.Fatal(h)
	}
	b.LastSeen = a.LastSeen.Add(-time.Second)
	if h := InvestigationHypotheses([]telemetry.Detection{a, b}); len(h) != 0 {
		t.Fatal("reverse chronology accepted", h)
	}
	b.LastSeen = a.LastSeen.Add(time.Minute)
	b.Version = 2
	if h := InvestigationHypotheses([]telemetry.Detection{a, b}); len(h) != 0 {
		t.Fatal("unknown rule version interpreted", h)
	}
	a.Rule = "fess.allowed_after_blocks"
	b.Rule = "threatfox.ip_match"
	b.Version = 1
	b.LastSeen = a.LastSeen
	if h := InvestigationHypotheses([]telemetry.Detection{b, a}); len(h) != 1 || h[0].Rule != "investigation.allowed_with_ioc" {
		t.Fatal(h)
	}
	b.Evidence = []string{telemetry.ID("different raw")}
	if h := InvestigationHypotheses([]telemetry.Detection{a, b}); len(h) > 0 {
		t.Fatal("IP alone inferred same request", h)
	}
}
