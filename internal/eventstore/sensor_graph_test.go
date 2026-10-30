// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/flowexport"
	"github.com/rkislov/cerber/internal/telemetry"
	"github.com/rkislov/cerber/internal/testutil/flowwire"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestSensorGraphUsesTupleTimeAndCurrentScope(t *testing.T) {
	s := storageFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Minute)
	line := fmt.Sprintf(`{"timestamp":%q,"event_type":"flow","flow_id":42,"src_ip":"192.0.2.1","dest_ip":"192.0.2.2","src_port":12345,"dest_port":445,"proto":"TCP","flow":{"start":%q,"end":%q,"pkts_toserver":3}}`, at.Add(time.Second).Format(time.RFC3339Nano), at.Add(-time.Second).Format(time.RFC3339Nano), at.Add(time.Second).Format(time.RFC3339Nano))
	p, _ := json.Marshal(telemetry.SensorEnvelope{Input: "tap", Peer: "local", Transport: "file", Profile: "suricata", Line: line})
	raw := telemetry.Raw{ID: telemetry.ID("eve"), Source: "network:suricata", Cursor: "1", ObservedAt: at, Data: p}
	if _, e := s.Accept(ctx, "sensor", "observer", telemetry.Batch{SchemaVersion: 1, ID: telemetry.ID("batch"), AgentID: "sensor", Records: []telemetry.Raw{raw}}); e != nil {
		t.Fatal(e)
	}
	if e := s.Step(ctx); e != nil {
		t.Fatal(e)
	}
	a := telemetry.ChainStep{EventID: telemetry.ID("wfp"), AgentID: "host", AssetID: "host-asset", At: at, Code: "5156", WindowsActivity: &telemetry.WindowsActivity{SourceAddress: "192.0.2.1", DestinationAddress: "192.0.2.2", SourcePort: "12345", DestinationPort: "445", Protocol: "6"}}
	for _, excluded := range []bool{false, true} {
		c := telemetry.EventChain{Steps: []telemetry.ChainStep{a}}
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		e = sensorContext(ctx, tx, &c, func(n telemetry.Normalized) (bool, error) { return !(excluded && n.AgentID == "sensor"), nil })
		tx.Rollback()
		if e != nil {
			t.Fatal(e)
		}
		if excluded {
			if len(c.Steps) != 1 || len(c.Links) != 0 {
				t.Fatal("sensor policy exclusion bypassed")
			}
			continue
		}
		if len(c.Steps) != 2 || len(c.Links) != 1 || c.Links[0].Kind != "sensor_observation" || c.Steps[1].Identity.AccountSID != "" || c.Steps[1].User != "" || c.Steps[1].AssetID != "observer" {
			t.Fatalf("%+v", c)
		}
	}
	n := telemetry.Normalize(telemetry.RawRecord{AgentID: "sensor", AssetID: "observer", ReceivedAt: at.Add(2 * time.Second), Raw: raw})
	if !sensorMatches(a, n) {
		t.Fatal("matching flow lost")
	}
	n.DestinationPort = 446
	if sensorMatches(a, n) {
		t.Fatal("port ignored")
	}
	n.DestinationPort = 445
	a.At = at.Add(time.Minute)
	if sensorMatches(a, n) {
		t.Fatal("flow interval ignored")
	}
}

func TestClassQueryAndSensorQueryHaveIndexes(t *testing.T) {
	s := storageFixture(t)
	for _, q := range []string{`SELECT payload FROM normalized_events WHERE class='network_connection' AND status='parsed' ORDER BY sequence DESC LIMIT 51`, `SELECT payload FROM normalized_events WHERE class IN ('network_flow','network_alert') AND status='parsed' AND source_ip='192.0.2.1' AND event_time>='2026' ORDER BY event_time,sequence LIMIT 101`, `SELECT count(*) FROM normalized_events WHERE status='quarantine'`} {
		rows, e := s.db.Query("EXPLAIN QUERY PLAN " + q)
		if e != nil {
			t.Fatal(e)
		}
		plan := ""
		for rows.Next() {
			var a, b, c int
			var d string
			rows.Scan(&a, &b, &c, &d)
			plan += d
		}
		rows.Close()
		if !strings.Contains(plan, "INDEX") {
			t.Fatal(plan)
		}
	}
}

func TestV9IPFIXFlowsReachGraphButExportTimeIsNotConnectionTime(t *testing.T) {
	for _, version := range []uint16{9, 10} {
		s := storageFixture(t)
		ctx := context.Background()
		at := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
		var decoder flowexport.Decoder
		r, e := decoder.Decode("router", netip.MustParseAddrPort("192.0.2.254:50000"), flowwire.Packet(version, at, true), at, flowexport.DefaultTTL)
		if e != nil || len(r.Records) != 1 {
			t.Fatal(r, e)
		}
		profile := map[uint16]string{9: "netflow9", 10: "ipfix"}[version]
		env := telemetry.SensorEnvelope{Input: "router", Peer: "192.0.2.254", PeerPort: 50000, Transport: "udp", Profile: profile, Flow: &r.Records[0]}
		p, _ := json.Marshal(env)
		raw := telemetry.Raw{ID: telemetry.ID(profile), Source: "network:netflow", Cursor: "1", ObservedAt: at, Data: p}
		if _, e = s.Accept(ctx, "sensor", "observer", telemetry.Batch{SchemaVersion: 1, ID: telemetry.ID(profile, "batch"), AgentID: "sensor", Records: []telemetry.Raw{raw}}); e != nil {
			t.Fatal(e)
		}
		if e = s.Step(ctx); e != nil {
			t.Fatal(e)
		}
		a := telemetry.ChainStep{EventID: telemetry.ID("wfp"), AgentID: "host", AssetID: "endpoint", At: at.Add(-1500 * time.Millisecond), Code: "5156", WindowsActivity: &telemetry.WindowsActivity{SourceAddress: "192.0.2.1", DestinationAddress: "192.0.2.2", SourcePort: "12345", DestinationPort: "445", Protocol: "6"}}
		c := telemetry.EventChain{Steps: []telemetry.ChainStep{a}}
		tx, _ := s.db.BeginTx(ctx, nil)
		e = sensorContext(ctx, tx, &c, func(telemetry.Normalized) (bool, error) { return true, nil })
		tx.Rollback()
		if e != nil || len(c.Steps) != 2 || len(c.Links) != 1 || c.Steps[1].Network.Kind != profile || c.Steps[1].User != "" {
			t.Fatal(c, e)
		}
		// Remove valid time fields while retaining a valid address/port template.
		ev := r.Records[0]
		ev.Template = append([]byte{}, ev.Template[:24]...)
		binary.BigEndian.PutUint16(ev.Template[2:], 5)
		ev.Record = ev.Record[:13]
		env.Flow = &ev
		p, _ = json.Marshal(env)
		raw.Data = p
		n := telemetry.Normalize(telemetry.RawRecord{AgentID: "sensor", AssetID: "observer", ReceivedAt: at, Raw: raw})
		if n.Status != "parsed" || n.Network.Start != nil || n.EventTime != at || sensorMatches(a, n) {
			t.Fatal("export clock fabricated a connection", n)
		}
	}
}
