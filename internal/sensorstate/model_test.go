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
