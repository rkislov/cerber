// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/cerber/internal/incidents"
	"github.com/rkislov/cerber/internal/telemetry"
	"testing"
	"time"
)

func saveInvestigationFixture(t *testing.T, s *Store, d telemetry.Detection) {
	t.Helper()
	p, _ := json.Marshal(d)
	_, e := s.db.Exec("INSERT INTO detections(id,rule,agent_id,user_name,source_ip,event_time,payload) VALUES(?,?,?,?,?,?,?)", d.ID, d.Rule, d.AgentID, d.User, d.SourceIP, stamp(d.LastSeen), string(p))
	if e != nil {
		t.Fatal(e)
	}
}
func TestInvestigationDirectSnapshotAndAtomicBulkLink(t *testing.T) {
	s := storageFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seed := telemetry.Detection{ID: telemetry.ID("seed"), Rule: "auth.success_after_failures", Version: 1, AgentID: "agent", AssetID: "asset", User: "Alice", SourceIP: "192.0.2.1", LastSeen: now, Evidence: []string{telemetry.ID("seedraw")}, Title: "Fixture", Severity: "high"}
	saveInvestigationFixture(t, s, seed)
	next := seed
	next.ID = telemetry.ID("audit")
	next.Rule = "windows.audit_log_cleared"
	next.LastSeen = now.Add(time.Minute)
	next.Evidence = []string{telemetry.ID("auditraw")}
	saveInvestigationFixture(t, s, next)
	foreign := next
	foreign.ID = telemetry.ID("NAT-other-agent")
	foreign.AgentID = "other"
	saveInvestigationFixture(t, s, foreign)
	transitive := next
	transitive.ID = telemetry.ID("transitive")
	transitive.LastSeen = now.Add(31 * time.Minute)
	saveInvestigationFixture(t, s, transitive)
	card, e := s.IncidentCommand(ctx, incidents.Command{Action: "create", Title: "Fixture", Severity: "high", DetectionID: seed.ID}, "analyst", now)
	if e != nil {
		t.Fatal(e)
	}
	out, e := s.Investigation(ctx, card.ID, "")
	if e != nil || len(out.Related) != 1 || len(out.Hypotheses) != 1 || out.IncidentVersion != card.Version {
		t.Fatal(out, e)
	}
	if out.Related[0].Detection.ID != next.ID {
		t.Fatal(out)
	}
	if _, e = s.Investigation(ctx, card.ID, seed.ID); !errors.Is(e, incidents.ErrInvalid) {
		t.Fatal(e)
	}
	if _, e = s.Investigation(ctx, "", telemetry.ID("missing")); !errors.Is(e, incidents.ErrNotFound) {
		t.Fatal(e)
	}
	command := incidents.Command{Action: "link_many", ID: card.ID, Version: card.Version, DetectionIDs: []string{next.ID, telemetry.ID("missing")}, Text: "Same host and user; review evidence"}
	if _, e = s.IncidentCommand(ctx, command, "analyst", now); !errors.Is(e, incidents.ErrNotFound) {
		t.Fatal(e)
	}
	unchanged, _ := s.Incident(ctx, card.ID)
	if unchanged.Version != card.Version || unchanged.DetectionCount != 1 {
		t.Fatal("partial bulk mutation", unchanged)
	}
	command.DetectionIDs = []string{next.ID}
	linked, e := s.IncidentCommand(ctx, command, "analyst", now)
	if e != nil || linked.Version != card.Version+1 || linked.DetectionCount != 2 {
		t.Fatal(linked, e)
	}
	history, e := s.IncidentHistory(ctx, card.ID, 0, 20)
	if e != nil || history[0].Kind != "link_many" {
		t.Fatal(history, e)
	}
	if _, e = s.IncidentCommand(ctx, command, "analyst", now); !errors.Is(e, incidents.ErrConflict) {
		t.Fatal("stale write accepted", e)
	}
	command.Version = linked.Version
	command.DetectionIDs = []string{next.ID, next.ID}
	if _, e = s.IncidentCommand(ctx, command, "analyst", now); !errors.Is(e, incidents.ErrInvalid) {
		t.Fatal(e)
	}
}
func TestInvestigationFlagsDenseCandidateTruncation(t *testing.T) {
	s := storageFixture(t)
	now := time.Now()
	seed := telemetry.Detection{ID: telemetry.ID("seed"), Rule: "fess.allowed_after_blocks", Version: 1, AgentID: "agent", AssetID: "asset", SourceIP: "192.0.2.1", LastSeen: now, Evidence: []string{telemetry.ID("raw")}}
	saveInvestigationFixture(t, s, seed)
	for i := 0; i < 205; i++ {
		d := seed
		d.ID = telemetry.ID(fmt.Sprint(i))
		d.Rule = "threatfox.ip_match"
		saveInvestigationFixture(t, s, d)
	}
	v, e := s.Investigation(context.Background(), "", seed.ID)
	if e != nil || !v.Truncated || len(v.Related) > 100 || len(v.Hypotheses) > 20 {
		t.Fatal(v, e)
	}
}
