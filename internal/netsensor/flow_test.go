// SPDX-License-Identifier: Apache-2.0
package netsensor

import (
	"context"
	"github.com/rkislov/cerber/internal/eventstore"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/telemetry"
	"github.com/rkislov/cerber/internal/testutil/flowwire"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestV9IPFIXUDPQueueRestartAndHTTPDelivery(t *testing.T) {
	for _, version := range []uint16{9, 10} {
		t.Run(map[uint16]string{9: "v9", 10: "ipfix"}[version], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			path := filepath.Join(t.TempDir(), "queue.db")
			q, e := eventstore.Open(ctx, path)
			if e != nil {
				t.Fatal(e)
			}
			r := newReceiver(q, "sensor")
			format := map[uint16]string{9: "netflow9", 10: "ipfix"}[version]
			input := Input{ID: "flow", Format: format, Protocol: "udp", Allow: []string{"127.0.0.1/32"}}
			c, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			done := make(chan error, 1)
			go func() { done <- r.serveUDP(ctx, c, input) }()
			conn, e := net.Dial("udp", c.LocalAddr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			at := time.Now().UTC().Truncate(time.Second)
			conn.Write(flowwire.Packet(version, at, false))
			deadline := time.Now().Add(time.Second)
			for r.flowUnknown.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if r.flowUnknown.Load() != 1 || r.stored.Load() != 0 {
				t.Fatal("missing template was guessed")
			}
			conn.Write(flowwire.Packet(version, at, true))
			deadline = time.Now().Add(3 * time.Second)
			for r.stored.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if r.stored.Load() != 1 {
				t.Fatal("UDP flow not stored")
			}
			cancel()
			if e = <-done; e != nil {
				t.Fatal(e)
			}
			q.Close()
			ctx = context.Background()
			q, e = eventstore.Open(ctx, path)
			if e != nil {
				t.Fatal(e)
			}
			defer q.Close()
			b, e := q.NextBatch(ctx, "sensor")
			if e != nil {
				t.Fatal(e)
			}
			// No template cache remains, but the durable batch contains its snapshot.
			journal, e := eventstore.Open(ctx, ":memory:")
			if e != nil {
				t.Fatal(e)
			}
			defer journal.Close()
			credentials := ingest.Credentials{AgentID: "sensor", Token: strings.Repeat("a", 64)}
			server := httptest.NewServer(ingest.NewEventHandler(sensorBinding{credentials.AgentID, ingest.Hash([]byte(credentials.Token))}, journal))
			defer server.Close()
			client, e := ingest.NewClient(server.URL, credentials, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			receipt, e := client.SendEvents(ctx, b)
			if e != nil {
				t.Fatal(e)
			}
			retry, e := client.SendEvents(ctx, b)
			if e != nil || retry != receipt {
				t.Fatal("retry changed receipt", e)
			}
			if e = q.Ack(ctx, b, receipt); e != nil {
				t.Fatal(e)
			}
			if e = journal.Step(ctx); e != nil {
				t.Fatal(e)
			}
			rows, e := journal.ReadEvents(ctx, telemetry.Query{Source: "network:netflow", Class: "network_flow", Limit: 10})
			if e != nil || len(rows) != 1 {
				t.Fatal(rows, e)
			}
			n := rows[0]
			if n.Network.Kind != format || n.Network.ObservationDomain != 42 || n.Network.TemplateID != 256 || n.Network.ExporterPort == 0 || n.Network.Start == nil || n.Network.End == nil || n.SourceIP != "192.0.2.1" || n.DestinationPort != 445 || n.Identity != nil {
				t.Fatal(n)
			}
		})
	}
}
