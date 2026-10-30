// SPDX-License-Identifier: Apache-2.0
package netsensor

import (
	"context"
	"github.com/rkislov/cerber/internal/eventstore"
	"github.com/rkislov/cerber/internal/sensorstate"
	"github.com/rkislov/cerber/internal/telemetry"
	"github.com/rkislov/cerber/internal/testutil/sflowwire"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestSFlowManagedUDPQueueRestartAndNormalization(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path := filepath.Join(t.TempDir(), "queue.db")
	q, e := eventstore.Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	r := newReceiver(q, "sensor") // Allocate a free test endpoint.
	probe, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		t.Fatal(e)
	}
	address := probe.LocalAddr().String()
	probe.Close()
	config := Config{Spool: path}
	if e = r.configure(config); e != nil {
		t.Fatal(e)
	}
	policy := sensorstate.Policy{Revision: 1, UpdatedAt: time.Now().UTC(), Inputs: []sensorstate.Control{{ID: "sflow", Format: "sflow5", Listen: address, Enabled: true, Allow: []string{"127.0.0.1/32"}}}}
	if e = r.applyPolicy(policy, true); e != nil {
		t.Fatal(e)
	}
	if e = r.startFlows(ctx, func(e error) { t.Error(e) }); e != nil {
		t.Fatal(e)
	}
	p := sflowwire.Packet(false, 3, sflowwire.IPv4())
	if e = r.receive(ctx, r.activeInputs[0], netip.MustParseAddrPort("192.0.2.10:1234"), p); e == nil {
		t.Fatal("allowlist bypass")
	}
	conn, e := net.Dial("udp", address)
	if e != nil {
		t.Fatal(e)
	}
	conn.Write(p)
	conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	for r.stored.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if r.stored.Load() != 1 {
		t.Fatal("UDP not enqueued")
	}
	r.stopFlows()
	cancel()
	q.Close()
	ctx = context.Background()
	q, e = eventstore.Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	restored := newReceiver(q, "sensor")
	if e = restored.configure(config); e != nil || restored.activeInputs[0].Format != "sflow5" {
		t.Fatal(e)
	}
	b, e := q.NextBatch(ctx, "sensor")
	if e != nil {
		t.Fatal(e)
	}
	journal, e := eventstore.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer journal.Close()
	receipt, e := journal.Accept(ctx, "sensor", "observer", b)
	if e != nil {
		t.Fatal(e)
	}
	retry, e := journal.Accept(ctx, "sensor", "observer", b)
	if e != nil || retry != receipt {
		t.Fatal("retry", e)
	}
	if e = journal.Step(ctx); e != nil {
		t.Fatal(e)
	}
	rows, e := journal.ReadEvents(ctx, telemetry.Query{Class: "network_flow", Limit: 10})
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	n := rows[0]
	if !n.Network.Sampled || n.Network.Packets != 1 || n.Network.Bytes != 60 || n.Network.SamplingInterval != 100 || n.SourceIP != "192.0.2.1" || n.DestinationPort != 445 || n.Identity != nil {
		t.Fatal(n)
	}
}
