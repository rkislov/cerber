// SPDX-License-Identifier: Apache-2.0
package sensorstate_test

import (
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/sensorstate"
	"testing"
	"time"
)

func TestBoundedSensorHeartbeatAndControls(t *testing.T) {
	at := time.Now().UTC()
	s := sensorstate.Status{StartedAt: at, ObservedAt: at}
	for n := 0; n < 8; n++ {
		i := sensorstate.Input{ID: fmt.Sprint("input", n), Format: "ipfix", Protocol: "udp", Listen: "[2001:db8::1]:4739", Enabled: true, State: "listening", LastMessageAt: &at, LastErrorAt: &at, LastError: "missing_template"}
		for k := 0; k < 128; k++ {
			i.Allow = append(i.Allow, fmt.Sprintf("2001:db8:ffff:ffff:ffff:ffff:ffff:%x/128", k))
		}
		for k := 0; k < 8; k++ {
			i.Exporters = append(i.Exporters, sensorstate.Exporter{Peer: fmt.Sprintf("2001:db8:ffff:ffff:ffff:ffff:ffff:%x", k), Port: 65535, Domain: 4294967295, LastSeen: at})
		}
		s.Inputs = append(s.Inputs, i)
	}
	h := ingest.Heartbeat{SchemaVersion: 1, AgentID: "sensor", ObservedAt: at, Platform: "linux", Architecture: "arm64", CollectionStatus: "not_attempted", DeliveryStatus: "not_attempted", Sensor: &s}
	if e := h.Validate(); e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(h)
	if int64(len(b)) >= ingest.MaxHeartbeatBytes {
		t.Fatal("valid status exceeds transport limit", len(b))
	}
	for _, allow := range [][]string{nil, {"any"}, {"192.0.2.7/24"}, {"::ffff:192.0.2.1/128"}, {"127.0.0.1/32", "127.0.0.1/32"}} {
		if sensorstate.ValidAllow(allow) {
			t.Fatal("ambiguous allowlist", allow)
		}
	}
	if e := sensorstate.Match([]sensorstate.Control{{ID: "input0", Allow: []string{"192.0.2.0/24"}, TemplateTTLSeconds: 59}}, s.Inputs); e == nil {
		t.Fatal("short TTL")
	}
	s.Inputs[0].Exporters = append(s.Inputs[0].Exporters, s.Inputs[0].Exporters[0])
	if e := s.Validate(); e == nil {
		t.Fatal("unbounded exporters")
	}
}

func TestManagedListenerScopeLimitsAndBindCollisions(t *testing.T) {
	base := []sensorstate.Definition{{ID: "fixed", Format: "syslog", Protocol: "udp", Listen: "0.0.0.0:5514"}, {ID: "local", Format: "netflow9", Protocol: "udp", Listen: "127.0.0.1:2059"}}
	good := sensorstate.Control{ID: "created", Format: "ipfix", Listen: "[::1]:4739", Enabled: true, Allow: []string{"::1/128"}}
	if defs, e := sensorstate.Resolve([]sensorstate.Control{good}, base); e != nil || len(defs) != 3 {
		t.Fatal(defs, e)
	}
	cases := []sensorstate.Control{good, good, good, good, good, good, good, good}
	cases[0].ID = "fixed"
	cases[1].Listen = "127.0.0.1:5514"
	cases[2].Listen = "localhost:4739"
	cases[3].Listen = "127.0.0.1:0"
	cases[4].Listen = "[::ffff:127.0.0.1]:4739"
	cases[5].Listen = "[fe80::1%eth0]:4739"
	cases[6].Format = "suricata"
	cases[7].Listen = "224.0.0.1:4739"
	for _, c := range cases {
		if _, e := sensorstate.Resolve([]sensorstate.Control{c}, base); e == nil {
			t.Fatal("invalid binding accepted", c)
		}
	}
	for _, c := range []sensorstate.Control{{ID: "fixed", Removed: true}, {ID: "missing", Removed: true}, {ID: "local", Removed: true, Enabled: true}, {ID: "missing", Allow: []string{"127.0.0.1/32"}}} {
		if _, e := sensorstate.Resolve([]sensorstate.Control{c}, base); e == nil {
			t.Fatal("invalid deletion/override", c)
		}
	}
	allBase := []sensorstate.Definition{}
	controls := []sensorstate.Control{}
	for k := 0; k < 8; k++ {
		id := fmt.Sprint("base", k)
		allBase = append(allBase, sensorstate.Definition{ID: id, Format: "ipfix", Protocol: "udp", Listen: fmt.Sprintf("127.0.0.1:%d", 2050+k)})
		controls = append(controls, sensorstate.Control{ID: id, Removed: true}, sensorstate.Control{ID: fmt.Sprint("remote", k), Format: "netflow9", Listen: fmt.Sprintf("127.0.0.1:%d", 3050+k), Enabled: true, Allow: []string{"127.0.0.1/32"}})
	}
	if defs, e := sensorstate.Resolve(controls, allBase); e != nil || len(defs) != 8 {
		t.Fatal("bounded local tombstones", defs, e)
	}
	if _, e := sensorstate.Resolve([]sensorstate.Control{good}, allBase); e == nil {
		t.Fatal("more than eight active inputs")
	}
	if _, e := sensorstate.Resolve(controls[:len(controls)-1], allBase); e != nil {
		t.Fatal(e)
	}
}

func TestMonitoringBoundsAndIndependentExporterKeys(t *testing.T) {
	c := sensorstate.DefaultMonitor()
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	c.Watches = []sensorstate.Watch{{Input: "input", Peer: "192.0.2.1", SilenceSeconds: 180}, {Input: "input", Peer: "2001:db8::1", SilenceSeconds: 300}}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, peer := range []string{"router.local", "::ffff:192.0.2.1", "fe80::1%eth0", "0.0.0.0", "224.0.0.1"} {
		bad := c
		bad.Watches = []sensorstate.Watch{{Input: "input", Peer: peer, SilenceSeconds: 180}}
		if bad.Validate() == nil {
			t.Fatal("bad watch peer", peer)
		}
	}
	c.Watches = append(c.Watches, c.Watches[0])
	if c.Validate() == nil {
		t.Fatal("duplicate expectation")
	}
	c = sensorstate.DefaultMonitor()
	c.WindowSeconds = 179
	if c.Validate() == nil {
		t.Fatal("unbounded window")
	}
	c = sensorstate.DefaultMonitor()
	c.QueueBytes = 257 << 20
	if c.Validate() == nil {
		t.Fatal("unreachable queue threshold")
	}
}

func TestSFlowCapabilityAndNoTemplateTTL(t *testing.T) {
	c := sensorstate.Control{ID: "sflow", Format: "sflow5", Listen: "127.0.0.1:6343", Enabled: true, Allow: []string{"127.0.0.1/32"}}
	s := sensorstate.Status{InputManagement: 1}
	if sensorstate.MatchStatus([]sensorstate.Control{c}, s) == nil {
		t.Fatal("old sensor accepted sFlow")
	}
	s.SFlowVersion = 1
	if e := sensorstate.MatchStatus([]sensorstate.Control{c}, s); e != nil {
		t.Fatal(e)
	}
	c.TemplateTTLSeconds = 900
	if sensorstate.ValidateControls([]sensorstate.Control{c}) == nil {
		t.Fatal("sFlow template TTL")
	}
}
