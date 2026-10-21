// SPDX-License-Identifier: Apache-2.0
package endpoint

import (
	"context"
	"github.com/rkislov/cerber/internal/netscan"
	"testing"
	"time"
)

func TestNetworkLeaseResultAndSchedule(t *testing.T) {
	s, _ := fixture(t)
	ctx := context.Background()
	agent := "01cb1915ccf46c919d4f8ea96d801db6"
	if e := s.NetworkCommand(ctx, NetworkCommand{Action: "create", Plan: netscan.Plan{Name: "test", Agent: agent, CIDR: "192.0.2.1/32", Profile: "services", Interval: 15, Enabled: true}}, "admin"); e != nil {
		t.Fatal(e)
	}
	a, e := s.networkExchange(ctx, agent, nil)
	if e != nil || a == nil {
		t.Fatal(e)
	}
	b, e := s.networkExchange(ctx, agent, nil)
	if e != nil || b.ID != a.ID {
		t.Fatal("duplicate lease", e)
	}
	r := netscan.Result{ID: a.ID, State: "completed", Started: time.Now(), Finished: time.Now(), Hosts: []netscan.Host{{IP: "192.0.2.1", Services: []netscan.Service{{Port: 22}}}}}
	if _, e = s.networkExchange(ctx, agent, &r); e != nil {
		t.Fatal(e)
	}
	v, _ := s.NetworkView(ctx)
	if len(v.Assets) != 1 || !v.Assets[0].New || v.Runs[0].Result.State != "completed" {
		t.Fatal(v)
	}
	// Retrying a result is idempotent; the next interval must not start early.
	if a, e = s.networkExchange(ctx, agent, &r); e != nil || a != nil {
		t.Fatal("retry rescheduled", e)
	}
	if e = s.NetworkCommand(ctx, NetworkCommand{Action: "run", ID: v.Plans[0].ID}, "admin"); e != nil {
		t.Fatal(e)
	}
	a, _ = s.networkExchange(ctx, agent, nil)
	bad := r
	bad.ID = a.ID
	bad.Hosts = []netscan.Host{{IP: "198.51.100.1"}}
	if _, e = s.networkExchange(ctx, agent, &bad); e == nil {
		t.Fatal("out of scope report")
	}
	r.ID = a.ID
	r.Hosts = nil
	r.State = "failed"
	if _, e = s.networkExchange(ctx, agent, &r); e != nil {
		t.Fatal(e)
	}
	v, _ = s.NetworkView(ctx)
	if v.Assets[0].State != "observed" {
		t.Fatal("failure marked device missing")
	}
	if e = s.NetworkCommand(ctx, NetworkCommand{Action: "run", ID: v.Plans[0].ID}, "admin"); e != nil {
		t.Fatal(e)
	}
	a, _ = s.networkExchange(ctx, agent, nil)
	r.ID = a.ID
	r.State = "completed"
	s.networkExchange(ctx, agent, &r)
	v, _ = s.NetworkView(ctx)
	if v.Assets[0].State != "not_observed" {
		t.Fatal("absence not tracked")
	}
}
func TestNetworkCancelledLeaseNeverDelivered(t *testing.T) {
	s, _ := fixture(t)
	ctx := context.Background()
	agent := "01cb1915ccf46c919d4f8ea96d801db6"
	s.NetworkCommand(ctx, NetworkCommand{Action: "create", Plan: netscan.Plan{Name: "test", Agent: agent, CIDR: "192.0.2.1/32", Profile: "discovery", Interval: 15, Enabled: true}}, "admin")
	a, _ := s.networkExchange(ctx, agent, nil)
	if e := s.NetworkCommand(ctx, NetworkCommand{Action: "cancel", ID: a.ID}, "admin"); e != nil {
		t.Fatal(e)
	}
	if b, e := s.networkExchange(ctx, agent, nil); e != nil || b != nil {
		t.Fatal("cancelled delivered", e)
	}
}
