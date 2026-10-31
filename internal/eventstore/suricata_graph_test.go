// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/incidents"
	"github.com/rkislov/cerber/internal/rulepolicy"
	"github.com/rkislov/cerber/internal/telemetry"
	"testing"
	"time"
)

func eveFixture(t *testing.T, s *Store, agent, input string, at time.Time, kind string, flow uint64, port int) string {
	t.Helper()
	v := map[string]any{"timestamp": at.Format(time.RFC3339Nano), "event_type": kind, "flow_id": flow, "in_iface": "span0", "community_id": "1:test", "src_ip": "192.0.2.10", "dest_ip": "192.0.2.20", "src_port": 40000, "dest_port": port, "proto": "TCP"}
	if kind == "alert" {
		v["alert"] = map[string]any{"signature_id": 1000001, "rev": 2, "signature": "CERBER fixture", "severity": 1, "category": "test", "action": "allowed"}
	} else {
		v["flow"] = map[string]any{"start": at.Add(-10 * time.Second).Format(time.RFC3339Nano), "end": at.Format(time.RFC3339Nano), "pkts_toserver": 3}
	}
	line, _ := json.Marshal(v)
	data, _ := json.Marshal(telemetry.SensorEnvelope{Input: input, Peer: "local", Transport: "file", Profile: "suricata", Line: string(line)})
	raw := telemetry.Raw{ID: telemetry.ID(agent, input, string(line)), Source: "network:suricata", Cursor: telemetry.ID(string(data)), ObservedAt: at, Data: data}
	_, e := s.Accept(context.Background(), agent, "asset-"+agent, telemetry.Batch{SchemaVersion: 1, ID: telemetry.ID(raw.ID, "batch"), AgentID: agent, Records: []telemetry.Raw{raw}})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Step(context.Background()); e != nil {
		t.Fatal(e)
	}
	return telemetry.ID(agent, raw.ID)
}
func TestSuricataAlertPipelinePreviewSuppressionAndIncident(t *testing.T) {
	ctx := context.Background()
	s := storageFixture(t)
	at := time.Now().UTC().Add(-time.Minute)
	id := eveFixture(t, s, "sensor", "tap", at, "alert", 18446744073709551610, 445)
	eveFixture(t, s, "sensor", "tap", at.Add(time.Second), "alert", 43, 445)
	ds, e := s.ReadDetections(ctx, 0, 100)
	if e != nil || len(ds) != 1 {
		t.Fatal(ds, e)
	}
	d := ds[0]
	if !d.ObserverOnly || d.Rule != "suricata.alert" || d.Severity != "high" || d.User != "" || d.Chain == nil || d.Chain.Steps[0].Network.FlowID != "18446744073709551610" || d.Chain.Steps[0].Network.SignatureRevision != 2 {
		t.Fatal(d)
	}
	before := policyState(t, s)
	preview, e := s.PreviewRule(ctx, RulePreviewRequest{Rule: d.Rule, Config: rulepolicy.Defaults()[d.Rule], EventIDs: []string{id}}, nil, "")
	if e != nil || len(preview.Rows) != 1 || len(preview.Rows[0].Findings) != 1 || policyState(t, s) != before {
		t.Fatal(preview, e)
	}
	flow := eveFixture(t, s, "sensor", "tap", at.Add(3*time.Second), "flow", 18446744073709551610, 445)
	// Same ID but different sensor/input/port must not produce graph context.
	eveFixture(t, s, "other", "tap", at.Add(4*time.Second), "flow", 18446744073709551610, 445)
	eveFixture(t, s, "sensor", "other", at.Add(4*time.Second), "flow", 18446744073709551610, 445)
	eveFixture(t, s, "sensor", "tap", at.Add(4*time.Second), "flow", 18446744073709551610, 446)
	card, e := s.IncidentCommand(ctx, incidents.Command{Action: "create", Title: "Suricata fixture", Severity: "high", DetectionID: d.ID}, "owner", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	graph, e := s.IncidentGraph(ctx, card.ID)
	if e != nil || len(graph.Anchors) != 1 {
		t.Fatal(graph, e)
	}
	chain := graph.Anchors[0].Chain
	if len(chain.Steps) != 2 || len(chain.Links) != 1 || chain.Links[0].To != flow || chain.Links[0].Kind != "suricata_flow" {
		t.Fatalf("%+v", chain)
	}
	cfg := rulepolicy.Defaults()[d.Rule]
	cfg.ExcludeDestinationCIDRs = []string{"192.0.2.20/32"}
	_, e = s.ChangeRulePolicy(ctx, rulepolicy.Change{Action: "save", Rule: d.Rule, ExpectedRevision: 1, Config: cfg, Reason: "fixture exclusion"}, "owner")
	if e != nil {
		t.Fatal(e)
	}
	graph, e = s.IncidentGraph(ctx, card.ID)
	if e != nil || len(graph.Anchors[0].Chain.Steps) != 1 {
		t.Fatal("current context exclusion bypassed", graph, e)
	}
	eveFixture(t, s, "sensor", "tap", at.Add(2*time.Minute), "alert", 44, 445)
	ds, _ = s.ReadDetections(ctx, 0, 100)
	if len(ds) != 1 {
		t.Fatal("live exclusion bypassed", len(ds))
	}
}
func TestSuricataFlowIntervalAndIdentityAreRequired(t *testing.T) {
	at := time.Now().UTC()
	start, end := at.Add(-time.Second), at.Add(time.Second)
	x := &telemetry.NetworkObservation{Kind: "suricata.alert", Input: "eve", Transport: "file", Exporter: "local", FlowID: "42", Protocol: 6, SourcePort: 40000, CaptureInterface: "span0"}
	y := *x
	y.Kind = "suricata.flow"
	y.Start = &start
	y.End = &end
	a := telemetry.ChainStep{AgentID: "sensor", AssetID: "observer", At: at, SourceIP: "192.0.2.1", DestinationIP: "192.0.2.2", DestinationPort: 445, Network: x}
	n := telemetry.Normalized{AgentID: a.AgentID, AssetID: a.AssetID, Status: "parsed", SourceIP: a.SourceIP, DestinationIP: a.DestinationIP, DestinationPort: a.DestinationPort, Network: &y}
	if !sameSuricataFlow(a, n) {
		t.Fatal("match missing")
	}
	for _, change := range []func(*telemetry.Normalized){func(v *telemetry.Normalized) { v.AgentID = "other" }, func(v *telemetry.Normalized) { v.Network.FlowID = "43" }, func(v *telemetry.Normalized) { v.Network.CaptureInterface = "span1" }, func(v *telemetry.Normalized) { v.Network.Start = nil }, func(v *telemetry.Normalized) { wrong := at.Add(time.Minute); v.Network.Start = &wrong }, func(v *telemetry.Normalized) { v.DestinationPort = 446 }} {
		v := n
		w := y
		v.Network = &w
		change(&v)
		if sameSuricataFlow(a, v) {
			t.Fatal(fmt.Sprintf("incorrect match: %+v", v))
		}
	}
}
