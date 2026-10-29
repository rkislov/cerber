// SPDX-License-Identifier: Apache-2.0
package correlation

import (
	"github.com/rkislov/cerber/internal/telemetry"
	"testing"
	"time"
)

func TestConfiguredScanThresholdCountsPortsNotPackets(t *testing.T) {
	n := telemetry.Normalized{ID: telemetry.ID("n"), Status: "parsed", Class: "firewall", Action: "syn", SourceIP: "192.0.2.1", DestinationIP: "192.0.2.2", AgentID: "agent", AssetID: "asset", EventTime: time.Now()}
	history := []telemetry.Normalized{}
	for _, port := range []int{22, 22, 22, 80} {
		p := n
		p.ID = telemetry.ID("port", string(rune(port)))
		p.DestinationPort = port
		history = append(history, p)
	}
	if d := Configured("firewall.syn_scan", n, history, 3); d != nil {
		t.Fatal(d)
	}
	p := n
	p.DestinationPort = 443
	history = append(history, p)
	if d := Configured("firewall.syn_scan", n, history, 3); d == nil {
		t.Fatal("configured unique-port threshold ignored")
	}
}
