// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/incidents"
	"github.com/rkislov/cerber/internal/telemetry"
	"strconv"
	"testing"
	"time"
)

func TestIncidentGraphOnlyLinkedSnapshotsAndReadOnly(t *testing.T) {
	s := storageFixture(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-5 * time.Minute)
	for i, agent := range []string{"host1", "host2", "host3"} {
		chainEvent(t, s, agent, "asset-"+agent, at.Add(time.Duration(i)*time.Minute), 4624, chainFields())
	}
	ds, e := s.ReadDetections(ctx, 0, 100)
	if e != nil {
		t.Fatal(e)
	}
	var selected telemetry.Detection
	for _, d := range ds {
		if d.Rule == "chain.domain_account_hosts" {
			selected = d
		}
	}
	if selected.ID == "" {
		t.Fatal(ds)
	}
	card, e := s.IncidentCommand(ctx, incidents.Command{Action: "create", Title: "Graph fixture", Severity: "high", DetectionID: selected.ID}, "owner", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	before := policyState(t, s)
	v, e := s.IncidentGraph(ctx, card.ID)
	if e != nil || len(v.Anchors) != 1 || v.Anchors[0].ID != selected.ID || v.IncidentVersion != card.Version {
		t.Fatal(v, e)
	}
	if v.Anchors[0].Chain.Hosts != 3 || len(v.Anchors[0].Chain.Steps) != 3 || policyState(t, s) != before {
		t.Fatal("graph changed or lost snapshots", v)
	}
	after, e := s.Incident(ctx, card.ID)
	if e != nil || after.Version != card.Version {
		t.Fatal(after, e)
	}
	if _, e = s.IncidentGraph(ctx, "invalid"); !errors.Is(e, incidents.ErrInvalid) {
		t.Fatal(e)
	}
	if _, e = s.IncidentGraph(ctx, telemetry.ID("missing")); !errors.Is(e, incidents.ErrNotFound) {
		t.Fatal(e)
	}
	empty, e := s.IncidentCommand(ctx, incidents.Command{Action: "create", Title: "Empty graph", Severity: "medium"}, "owner", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	v, e = s.IncidentGraph(ctx, empty.ID)
	if e != nil || len(v.Anchors) != 0 {
		t.Fatal(v, e)
	}
}

func TestIncidentGraphBoundsLinkedChains(t *testing.T) {
	s := storageFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	card, e := s.IncidentCommand(ctx, incidents.Command{Action: "create", Title: "Bounded graph", Severity: "medium"}, "owner", now)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 21; i++ {
		d := telemetry.Detection{ID: telemetry.ID("graph-bound", strconv.Itoa(i)), Rule: "chain.ssh_key_hosts", Version: 1, Chain: &telemetry.EventChain{Version: 1}}
		p, _ := json.Marshal(d)
		if _, e = s.db.Exec("INSERT INTO detections(id,rule,agent_id,user_name,source_ip,event_time,payload) VALUES(?,?,?,?,?,?,?)", d.ID, d.Rule, "fixture", "", "", stamp(now.Add(time.Duration(i)*time.Second)), string(p)); e != nil {
			t.Fatal(e)
		}
		if _, e = s.db.Exec("INSERT INTO incident_detections VALUES(?,?)", card.ID, d.ID); e != nil {
			t.Fatal(e)
		}
	}
	v, e := s.IncidentGraph(ctx, card.ID)
	if e != nil || !v.Truncated || len(v.Anchors) != 20 {
		t.Fatal(v, e)
	}
}
