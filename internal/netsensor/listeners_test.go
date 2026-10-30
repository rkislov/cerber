// SPDX-License-Identifier: Apache-2.0
package netsensor

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/eventstore"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/sensorstate"
	"github.com/rkislov/cerber/internal/testutil/flowwire"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func freeFlowAddress(t *testing.T) string {
	t.Helper()
	c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		t.Fatal(e)
	}
	address := c.LocalAddr().String()
	c.Close()
	return address
}
func waitSensor(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("sensor condition did not settle")
}
func sendFlow(t *testing.T, address string, version uint16) {
	t.Helper()
	c, e := net.Dial("udp", address)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_, e = c.Write(flowwire.Packet(version, time.Now().UTC().Truncate(time.Second), true))
	if e != nil {
		t.Fatal(e)
	}
}
func assertReleased(t *testing.T, address string) {
	t.Helper()
	c, e := bindFlow(address)
	if e != nil {
		t.Fatal("listener remains bound", address, e)
	}
	c.Close()
}
func TestManagedFlowSocketsCreateRebindDeleteAndRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	q, e := eventstore.Open(ctx, filepath.Join(dir, "queue.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	base := Input{ID: "local", Format: "netflow9", Protocol: "udp", Listen: freeFlowAddress(t), Allow: []string{"127.0.0.1/32"}}
	c := Config{Spool: filepath.Join(dir, "policy-spool.db"), Inputs: []Input{base}}
	r := newReceiver(q, "sensor")
	if e = r.configure(c); e != nil {
		t.Fatal(e)
	}
	fail := make(chan error, 4)
	if e = r.startFlows(ctx, func(e error) { fail <- e }); e != nil {
		t.Fatal(e)
	}
	defer r.stopFlows()
	sendFlow(t, base.Listen, 9)
	waitSensor(t, func() bool { return r.stored.Load() == 1 })
	remote := sensorstate.Control{ID: "central", Format: "ipfix", Listen: freeFlowAddress(t), Allow: []string{"127.0.0.1/32"}, Enabled: true, TemplateTTLSeconds: 900}
	p := sensorstate.Policy{Revision: 1, UpdatedAt: time.Now().UTC(), Inputs: []sensorstate.Control{remote}}
	if e = r.applyPolicy(p, true); e != nil {
		t.Fatal(e)
	}
	sendFlow(t, remote.Listen, 10)
	waitSensor(t, func() bool { return r.stored.Load() == 2 })
	firstRemote := remote.Listen
	remote.Listen = freeFlowAddress(t)
	p.Revision = 2
	p.Inputs = []sensorstate.Control{remote}
	if e = r.applyPolicy(p, true); e != nil {
		t.Fatal(e)
	}
	assertReleased(t, firstRemote)
	sendFlow(t, remote.Listen, 10)
	waitSensor(t, func() bool { return r.stored.Load() == 3 })
	p.Revision = 3
	p.Inputs = append(p.Inputs, sensorstate.Control{ID: base.ID, Removed: true})
	if e = r.applyPolicy(p, true); e != nil {
		t.Fatal(e)
	}
	assertReleased(t, base.Listen)
	if len(r.snapshot(nil).Inputs) != 1 {
		t.Fatal("local tombstone ignored")
	}
	r.stopFlows()
	r2 := newReceiver(q, "sensor")
	if e = r2.configure(c); e != nil {
		t.Fatal(e)
	}
	if e = r2.startFlows(ctx, func(e error) { fail <- e }); e != nil {
		t.Fatal(e)
	}
	defer r2.stopFlows()
	if s := r2.snapshot(nil); s.AppliedRevision != 3 || len(s.Inputs) != 1 || s.Inputs[0].ID != "central" {
		t.Fatal(s)
	}
	assertReleased(t, base.Listen)
	sendFlow(t, remote.Listen, 10)
	waitSensor(t, func() bool { return r2.stored.Load() == 1 })
	// Reuse the already-open endpoint for a new input ID and wire format.
	p.Revision = 4
	p.Inputs[0].ID = "replacement"
	p.Inputs[0].Format = "netflow9"
	if e = r2.applyPolicy(p, true); e != nil {
		t.Fatal(e)
	}
	sendFlow(t, remote.Listen, 9)
	waitSensor(t, func() bool { return r2.stored.Load() == 2 })
	s := r2.snapshot(nil)
	if s.Inputs[0].ID != "replacement" || s.Inputs[0].Counters.Stored != 1 {
		t.Fatal("old reader routed into removed input", s)
	}
	p.Revision = 5
	p.Inputs = []sensorstate.Control{{ID: base.ID, Removed: true}}
	if e = r2.applyPolicy(p, true); e != nil {
		t.Fatal(e)
	}
	assertReleased(t, remote.Listen)
	s = r2.snapshot(nil)
	if len(s.Inputs) != 0 || s.Validate() != nil || len(r2.states) != 0 {
		t.Fatal("last input removal", s)
	}
	count, _, e := q.EventQueueUsage(ctx, "sensor")
	if e != nil || count != 5 {
		t.Fatal("listener deletion lost durable records", count, e)
	}
	select {
	case e := <-fail:
		t.Fatal("intentional close became receiver failure", e)
	default:
	}
}
func TestManagedFlowBindAndPersistenceFailureKeepRunningConfiguration(t *testing.T) {
	ctx := context.Background()
	q, e := eventstore.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	base := Input{ID: "original", Format: "ipfix", Protocol: "udp", Listen: freeFlowAddress(t), Allow: []string{"127.0.0.1/32"}}
	c := Config{Spool: filepath.Join(t.TempDir(), "queue.db"), Inputs: []Input{base}}
	r := newReceiver(q, "sensor")
	if e = r.configure(c); e != nil {
		t.Fatal(e)
	}
	failures := make(chan error, 2)
	if e = r.startFlows(ctx, func(e error) { failures <- e }); e != nil {
		t.Fatal(e)
	}
	defer r.stopFlows()
	p := sensorstate.Policy{Revision: 1, UpdatedAt: time.Now().UTC()}
	if e = r.applyPolicy(p, true); e != nil {
		t.Fatal(e)
	}
	cached, _ := os.ReadFile(r.policyPath)
	held, e := bindFlow(freeFlowAddress(t))
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	available := freeFlowAddress(t)
	p.Revision = 2
	p.Inputs = []sensorstate.Control{{ID: "prepared", Format: "netflow9", Listen: available, Allow: base.Allow, Enabled: true}, {ID: "occupied", Format: "ipfix", Listen: held.LocalAddr().String(), Allow: base.Allow, Enabled: true}}
	if e = r.applyPolicy(p, true); e == nil {
		t.Fatal("occupied socket accepted")
	}
	s := r.snapshot(nil)
	if s.AppliedRevision != 1 || s.ConfigError != "policy_bind_failed" || s.ConfigErrorInput != "occupied" || len(s.Inputs) != 1 {
		t.Fatal(s)
	}
	after, _ := os.ReadFile(r.policyPath)
	if !bytes.Equal(cached, after) {
		t.Fatal("failed bind persisted")
	}
	assertReleased(t, available)
	sendFlow(t, base.Listen, 10)
	waitSensor(t, func() bool { return r.stored.Load() == 1 })
	r.policyPath = filepath.Join(t.TempDir(), "missing", "policy.json")
	p.Inputs = p.Inputs[:1]
	if e = r.applyPolicy(p, true); e == nil {
		t.Fatal("failed persistence accepted")
	}
	assertReleased(t, available)
	if s = r.snapshot(nil); s.AppliedRevision != 1 || s.ConfigError != "policy_persist_failed" {
		t.Fatal(s)
	}
	sendFlow(t, base.Listen, 10)
	waitSensor(t, func() bool { return r.stored.Load() == 2 })
	select {
	case e := <-failures:
		t.Fatal(e)
	default:
	}
}
func TestCachedUnavailableListenerCanBeRemovedThroughHeartbeat(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("Run advertises native supported platforms; covered by Linux/Windows CI")
	}

	dir := t.TempDir()
	held, e := bindFlow(freeFlowAddress(t))
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	now := time.Now().UTC()
	creds := ingest.Credentials{AgentID: "sensor", Token: strings.Repeat("a", 64)}
	secret := filepath.Join(dir, "credentials.json")
	data, _ := json.Marshal(creds)
	if e = os.WriteFile(secret, data, 0600); e != nil {
		t.Fatal(e)
	}
	observed := make(chan ingest.Heartbeat, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/agent/heartbeat" {
			http.NotFound(w, req)
			return
		}
		var h ingest.Heartbeat
		if json.NewDecoder(req.Body).Decode(&h) != nil || h.Validate() != nil {
			http.Error(w, "bad heartbeat", 400)
			return
		}
		if req.Header.Get("Authorization") != "Bearer "+creds.Token {
			http.Error(w, "unauthorized", 401)
			return
		}
		select {
		case observed <- h:
		default:
		}
		json.NewEncoder(w).Encode(ingest.HeartbeatReceipt{AgentID: h.AgentID, ObservedAt: h.ObservedAt, ReceivedAt: time.Now().UTC(), SensorPolicy: &sensorstate.Policy{Revision: 2, UpdatedAt: now, Inputs: []sensorstate.Control{}}})
	}))
	defer server.Close()
	c := Config{SchemaVersion: 1, Server: server.URL, Credentials: secret, Spool: filepath.Join(dir, "queue.db"), Inputs: []Input{}}
	r := newReceiver(nil, "sensor")
	if e = r.configure(c); e != nil {
		t.Fatal(e)
	}
	p := sensorstate.Policy{Revision: 1, UpdatedAt: now, Inputs: []sensorstate.Control{{ID: "blocked", Format: "ipfix", Listen: held.LocalAddr().String(), Enabled: true, Allow: []string{"127.0.0.1/32"}}}}
	if e = r.applyPolicy(p, true); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c, io.Discard) }()
	select {
	case h := <-observed:
		if h.Sensor == nil || h.Sensor.ConfigError != "policy_bind_failed" || h.Sensor.AppliedRevision != 0 {
			t.Fatal(h)
		}
	case e := <-done:
		t.Fatal("control channel stopped", e)
	case <-time.After(5 * time.Second):
		t.Fatal("no repair heartbeat")
	}
	waitSensor(t, func() bool {
		b, e := os.ReadFile(r.policyPath)
		var cache cachedPolicy
		return e == nil && json.Unmarshal(b, &cache) == nil && cache.Policy.Revision == 2 && len(cache.Policy.Inputs) == 0
	})
	cancel()
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestUnavailableCachedFlowStatusAndRecovery(t *testing.T) {
	held, e := bindFlow(freeFlowAddress(t))
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	c := Config{Spool: filepath.Join(t.TempDir(), "queue.db"), Inputs: []Input{}}
	initial := newReceiver(nil, "sensor")
	if e = initial.configure(c); e != nil {
		t.Fatal(e)
	}
	p := sensorstate.Policy{Revision: 1, UpdatedAt: time.Now().UTC(), Inputs: []sensorstate.Control{{ID: "occupied", Format: "ipfix", Listen: held.LocalAddr().String(), Enabled: true, Allow: []string{"127.0.0.1/32"}}}}
	if e = initial.applyPolicy(p, true); e != nil {
		t.Fatal(e)
	}
	r := newReceiver(nil, "sensor")
	if e = r.configure(c); e != nil {
		t.Fatal(e)
	}
	if e = r.startFlows(context.Background(), func(error) {}); e == nil {
		t.Fatal("occupied socket reopened")
	}
	defer r.stopFlows()
	s := r.snapshot(nil)
	if e = s.Validate(); e != nil {
		t.Fatal(s, e)
	}
	if s.AppliedRevision != 0 || s.ConfigError != "policy_bind_failed" || s.Inputs[0].LastError != "listener_unavailable" {
		t.Fatal(s)
	}
	p.Revision = 2
	p.Inputs = nil
	if e = r.applyPolicy(p, true); e != nil {
		t.Fatal(e)
	}
	s = r.snapshot(nil)
	if s.AppliedRevision != 2 || s.ConfigError != "" || len(s.Inputs) != 0 || s.Validate() != nil {
		t.Fatal(s)
	}
}
