// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"
)

func TestSensorSyslogPreservesObserverAndDoesNotInventIdentity(t *testing.T) {
	at := time.Now().UTC()
	for _, line := range []string{`<165>1 ` + at.Format(time.RFC3339Nano) + ` claimed-router daemon 1 ID [x key="a\]b"][y x="z"] link down`, `<34>Oct 30 10:12:13 claimed-switch port: link down`} {
		p, _ := json.Marshal(SensorEnvelope{Input: "switches", Peer: "192.0.2.10", Transport: "tcp", Profile: "syslog", Line: line})
		n := Normalize(RawRecord{AgentID: "sensor", AssetID: "observer", ReceivedAt: at, Raw: Raw{ID: ID(line), Source: "network:syslog", ObservedAt: at, Data: p}})
		if n.Status != "parsed" || n.Class != "network_device" || n.Network.Exporter != "192.0.2.10" || n.SourceIP != "" || n.User != "" || n.Identity != nil || n.AssetID != "observer" {
			t.Fatalf("%+v", n)
		}
	}
	for _, line := range []string{"<999>1 broken", "<165>1 - host app proc msg bad", "<165>1 - host app proc msg [unclosed", "<1>1 - host app proc msg [x]\nforged"} {
		if _, _, _, _, e := parseSyslog(line, at); e == nil {
			t.Fatal("accepted malformed syslog", line)
		}
	}
}

func TestNetFlow5StrictBoundsAndWrap(t *testing.T) {
	p := make([]byte, 72)
	u16 := binary.BigEndian.PutUint16
	u32 := binary.BigEndian.PutUint32
	u16(p, 5)
	u16(p[2:], 1)
	u32(p[4:], 1000)
	u32(p[8:], uint32(time.Now().Unix()))
	u32(p[16:], 42)
	copy(p[24:], []byte{192, 0, 2, 1, 192, 0, 2, 2})
	u32(p[40:], 10)
	u32(p[44:], 100)
	u32(p[48:], ^uint32(0)-999)
	u32(p[52:], 500)
	u16(p[56:], 50000)
	u16(p[58:], 445)
	p[62] = 6
	u16(p[22:], 0x400a)
	flows, e := DecodeNetFlow5(p)
	if e != nil || len(flows) != 1 {
		t.Fatal(e)
	}
	f := flows[0]
	if f.End.Sub(f.Start) != 1500*time.Millisecond || f.Source != "192.0.2.1" || f.DestinationPort != 445 || f.SamplingMode != 1 || f.SamplingInterval != 10 || f.Packets != 10 {
		t.Fatalf("%+v", f)
	}
	if _, e = DecodeNetFlow5(p[:71]); e == nil {
		t.Fatal("truncation accepted")
	}
	p[1] = 9
	if _, e = DecodeNetFlow5(p); e == nil {
		t.Fatal("v9 decoded without template")
	}
}

func TestSuricataAlertHasNoInventedProcessOrVerdict(t *testing.T) {
	at := time.Now().UTC()
	line := `{"timestamp":"` + at.Format("2006-01-02T15:04:05.999999-0700") + `","event_type":"alert","flow_id":18446744073709551610,"src_ip":"::ffff:192.0.2.1","dest_ip":"192.0.2.2","src_port":12345,"dest_port":445,"proto":"TCP","alert":{"signature_id":42,"signature":"Test IDS","severity":2,"action":"allowed"}}`
	p, _ := json.Marshal(SensorEnvelope{Input: "tap", Peer: "local", Transport: "file", Profile: "suricata", Line: line})
	n := Normalize(RawRecord{AgentID: "sensor", AssetID: "observer", ReceivedAt: at, Raw: Raw{ID: ID(line), Source: "network:suricata", ObservedAt: at, Data: p}})
	if n.Status != "parsed" || n.Class != "network_alert" || n.Network.FlowID != "18446744073709551610" || n.SourceIP != "192.0.2.1" || n.Identity != nil || n.WindowsActivity != nil || n.Outcome != "unknown" {
		t.Fatalf("%+v", n)
	}
}
