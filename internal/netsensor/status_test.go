// SPDX-License-Identifier: Apache-2.0
package netsensor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/cerber/internal/eventstore"
	"github.com/rkislov/cerber/internal/sensorstate"
	"github.com/rkislov/cerber/internal/testutil/flowwire"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestSensorControlsStatisticsRestartAndCacheIsolation(t *testing.T) {
	ctx := context.Background()
	spool, e := eventstore.Open(ctx, filepath.Join(t.TempDir(), "queue.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer spool.Close()
	i := Input{ID: "v9", Format: "netflow9", Protocol: "udp", Listen: "127.0.0.1:12059", Allow: []string{"127.0.0.0/8"}}
	j := i
	j.ID = "ipfix"
	j.Format = "ipfix"
	j.Listen = "127.0.0.1:14739"
	c := Config{Spool: filepath.Join(t.TempDir(), "spool.db"), Inputs: []Input{i, j}}
	r := newReceiver(spool, "sensor")
	if e = r.configure(c); e != nil {
		t.Fatal(e)
	}
	peer := netip.MustParseAddrPort("127.0.0.1:9999")
	at := time.Now().UTC().Truncate(time.Second)
	if e = r.receive(ctx, i, peer, flowwire.Packet(9, at, false)); e != nil {
		t.Fatal(e)
	}
	if e = r.receive(ctx, i, peer, flowwire.Packet(9, at, true)); e != nil {
		t.Fatal(e)
	}
	if e = r.receive(ctx, j, peer, flowwire.Packet(10, at, true)); e != nil {
		t.Fatal(e)
	}
	report := r.snapshot(c.Inputs)
	if e = report.Validate(); e != nil {
		t.Fatal(report, e)
	}
	a := report.Inputs[0]
	if a.Counters.Messages != 2 || a.Counters.Stored != 1 || a.Counters.UnknownSets != 1 || a.Counters.Templates != 1 || a.LastError != "missing_template" || a.State != "receiving" || len(a.Exporters) != 1 || a.Exporters[0].Domain != 42 {
		t.Fatalf("bad metrics %+v", a)
	}
	if a.IntervalMessages != 2 || r.snapshot(c.Inputs).Inputs[0].IntervalMessages != 0 {
		t.Fatal("bad interval")
	}
	p := sensorstate.Policy{Revision: 1, UpdatedAt: time.Now().UTC(), Inputs: []sensorstate.Control{{ID: "v9", Enabled: false, Allow: []string{"127.0.0.1/32"}, TemplateTTLSeconds: 300}}}
	if e = r.applyPolicy(p, true); e != nil {
		t.Fatal(e)
	}
	if e = r.receive(ctx, i, peer, flowwire.Packet(9, at, true)); e == nil {
		t.Fatal("paused input accepted data")
	}
	report = r.snapshot(c.Inputs)
	if report.AppliedRevision != 1 || report.Inputs[0].Enabled || report.Inputs[0].State != "paused" {
		t.Fatal(report)
	}
	// Changing v9 must not evict IPFIX templates on the other input.
	if e = r.receive(ctx, j, peer, flowwire.Packet(10, at, false)); e != nil {
		t.Fatal(e)
	}
	if r.snapshot(c.Inputs).Inputs[1].Counters.Stored != 2 {
		t.Fatal("unrelated template evicted")
	}
	r2 := newReceiver(spool, "sensor")
	if e = r2.configure(c); e != nil {
		t.Fatal(e)
	}
	if r2.snapshot(c.Inputs).AppliedRevision != 1 {
		t.Fatal("lost persisted policy")
	}
	if e = r2.receive(ctx, i, peer, flowwire.Packet(9, at, true)); e == nil {
		t.Fatal("pause lost after restart")
	}
	info, _ := os.Stat(r2.policyPath)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	p.Revision = 2
	p.Inputs[0].Enabled = true
	if e = r2.applyPolicy(p, true); e != nil {
		t.Fatal(e)
	}
	if e = r2.receive(ctx, i, netip.MustParseAddrPort("127.0.0.2:9999"), flowwire.Packet(9, at, true)); e == nil {
		t.Fatal("allowlist bypass")
	}
	if e = r2.receive(ctx, i, peer, flowwire.Packet(9, at, false)); e != nil {
		t.Fatal(e)
	}
	if r2.snapshot(c.Inputs).Inputs[0].LastError != "missing_template" {
		t.Fatal("stale template survived policy")
	}
	if e = r2.receive(ctx, i, peer, flowwire.Packet(9, at, true)); e != nil {
		t.Fatal(e)
	}
	r2.policyPath = filepath.Join(t.TempDir(), "nonexistent", "policy.json")
	p.Revision = 3
	p.Inputs[0].Enabled = false
	if e = r2.applyPolicy(p, true); e == nil {
		t.Fatal("persist failure ignored")
	}
	report = r2.snapshot(c.Inputs)
	if report.AppliedRevision != 2 || !report.Inputs[0].Enabled || report.ConfigError != "policy_persist_failed" {
		t.Fatal(report)
	}
	// Policy for a different local configuration must never silently re-enable it.
	c.Inputs[0].Listen = "127.0.0.1:12060"
	r3 := newReceiver(spool, "sensor")
	if e = r3.configure(c); e == nil {
		t.Fatal("local configuration conflict ignored")
	}
}
func TestSensorExporterMetricsBoundedAndSnapshotDetached(t *testing.T) {
	ctx := context.Background()
	spool, e := eventstore.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer spool.Close()
	r := newReceiver(spool, "sensor")
	i := Input{ID: "ipfix", Format: "ipfix", Protocol: "udp", Listen: "127.0.0.1:4739", Allow: []string{"127.0.0.0/8"}}
	for n := 1; n <= 12; n++ {
		e = r.receive(ctx, i, netip.MustParseAddrPort(fmt.Sprintf("127.0.0.%d:9999", n)), []byte{0, 10})
		if e == nil {
			t.Fatal("bad packet accepted")
		}
	}
	s := r.snapshot([]Input{i})
	if len(s.Inputs[0].Exporters) != 8 || s.Inputs[0].ExportersOverflow != 4 || s.Inputs[0].Counters.Rejected != 12 || s.Inputs[0].LastError != "invalid_packet" {
		t.Fatal(s)
	}
	s.Inputs[0].Exporters[0].Peer = "bad"
	s.Inputs[0].Allow[0] = "bad"
	if e = r.snapshot([]Input{i}).Validate(); e != nil {
		t.Fatal("mutable snapshot", e)
	}
	b, _ := json.Marshal(s)
	if len(b) > 16384 {
		t.Fatal(len(b))
	}
	if !errors.Is(r.applyPolicy(sensorstate.Policy{Revision: 1, UpdatedAt: time.Now(), Inputs: []sensorstate.Control{{ID: "absent", Allow: []string{"127.0.0.1/32"}}}}, false), sensorstate.ErrInvalid) {
		t.Fatal("unknown input allowed")
	}
}
