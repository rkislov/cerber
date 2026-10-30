// SPDX-License-Identifier: Apache-2.0
package netsensor

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/eventstore"
	"github.com/rkislov/cerber/internal/telemetry"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFraming(t *testing.T) {
	for _, s := range []string{"<1>hello\n", "8 <1>hello"} {
		p, e := ReadFrame(bufio.NewReaderSize(strings.NewReader(s), maxMessage+2))
		if e != nil || string(p) != "<1>hello" {
			t.Fatal(string(p), e)
		}
	}
	for _, s := range []string{"9999999 abc", "99999 abc", "9 short", "partial", strings.Repeat("x", maxMessage+3) + "\n"} {
		if _, e := ReadFrame(bufio.NewReaderSize(strings.NewReader(s), maxMessage+2)); e == nil {
			t.Fatal("invalid frame accepted")
		}
	}
}

func TestDurableReceiverRetryAndImmutablePeer(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "queue.db")
	s, e := eventstore.Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	r := newReceiver(s, "sensor")
	i := Input{ID: "switches", Format: "syslog", Protocol: "tcp"}
	data := []byte("<34>Oct 30 10:12:13 spoofed-host interface: up")
	if e = r.accept(ctx, i, "192.0.2.7", data); e != nil {
		t.Fatal(e)
	}
	b, e := s.NextBatch(ctx, "sensor")
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = eventstore.Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	again, e := s.NextBatch(ctx, "sensor")
	if e != nil || again.ID != b.ID {
		t.Fatal("restart lost pending batch", e)
	}
	var v telemetry.SensorEnvelope
	json.Unmarshal(again.Records[0].Data, &v)
	if v.Peer != "192.0.2.7" || v.Line != string(data) {
		t.Fatal(v)
	}
	if e = s.Ack(ctx, again, telemetry.Receipt{AgentID: "sensor", BatchID: "wrong", Count: 1, ReceivedAt: time.Now()}); e == nil {
		t.Fatal("invalid acknowledgement accepted")
	}
	if e = s.Ack(ctx, again, telemetry.Receipt{AgentID: "sensor", BatchID: again.ID, Count: 1, ReceivedAt: time.Now()}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.NextBatch(ctx, "sensor"); e != telemetry.ErrNotFound {
		t.Fatal(e)
	}
}

func TestUDPNetFlowAndTCPAdmission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, e := eventstore.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	r := newReceiver(s, "sensor")
	c, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	done := make(chan error, 1)
	i := Input{ID: "flow", Format: "netflow5", Protocol: "udp", Allow: []string{"127.0.0.1/32"}}
	go func() { done <- r.serveUDP(ctx, c, i) }()
	p := make([]byte, 72)
	binary.BigEndian.PutUint16(p, 5)
	binary.BigEndian.PutUint16(p[2:], 1)
	binary.BigEndian.PutUint32(p[8:], uint32(time.Now().Unix()))
	conn, e := net.Dial("udp", c.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.Write(p)
	deadline := time.Now().Add(3 * time.Second)
	for r.stored.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.stored.Load() != 1 {
		t.Fatal("UDP not stored")
	}
	p[1] = 9
	conn.Write(p)
	deadline = time.Now().Add(time.Second)
	for r.rejected.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.rejected.Load() == 0 {
		t.Fatal("unsupported version not counted")
	}
	if i.permits(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("allowlist bypass")
	}
	cancel()
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestTCPReceiverAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, e := eventstore.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	r := newReceiver(s, "sensor")
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	done := make(chan error, 1)
	i := Input{ID: "syslog", Format: "syslog", Protocol: "tcp", Allow: []string{"127.0.0.1/32"}}
	go func() { done <- r.serveStream(ctx, l, i) }()
	c, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	line := "<34>Oct 30 10:12:13 switch port: up"
	fmt.Fprintf(c, "%d %s%s\n", len(line), line, line)
	deadline := time.Now().Add(3 * time.Second)
	for r.stored.Load() != 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.stored.Load() != 2 {
		t.Fatal("TCP framing lost records")
	}
	cancel()
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown stuck on idle stream")
	}
}

func TestRemoteConfigRequiresExplicitTrust(t *testing.T) {
	dir := t.TempDir()
	c := Config{SchemaVersion: 1, Credentials: filepath.Join(dir, "credentials.json"), Spool: filepath.Join(dir, "queue.db"), Inputs: []Input{{ID: "s", Format: "syslog", Protocol: "tcp", Listen: "0.0.0.0:5514", Allow: []string{"192.0.2.0/24"}}}}
	if c.Validate() == nil {
		t.Fatal("remote plaintext silently enabled")
	}
	c.Inputs[0].AllowPlainRemote = true
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	c.Inputs[0].Allow = nil
	if c.Validate() == nil {
		t.Fatal("wildcard peers accepted")
	}
}
