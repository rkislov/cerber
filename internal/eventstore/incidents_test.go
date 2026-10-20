// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"errors"
	"github.com/rkislov/cerber/internal/incidents"
	"github.com/rkislov/cerber/internal/telemetry"
	"path/filepath"
	"testing"
	"time"
)

func TestIncidentWorkflowHistoryAndVersionGuard(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	a := telemetry.ID("a")
	if _, e = s.Accept(ctx, a, "asset", batch(t, a, 0, "audit")); e != nil {
		t.Fatal(e)
	}
	if e = s.Step(ctx); e != nil {
		t.Fatal(e)
	}
	detections, _ := s.ReadDetections(ctx, 0, 100)
	d := detections[0]
	now := time.Now()
	card, e := s.IncidentCommand(ctx, incidents.Command{Action: "create", Title: "Incident fixture", Description: "Evidence review", Severity: "high", Assignee: "analyst", DetectionID: d.ID}, "analyst", now)
	if e != nil || card.Version != 1 || card.DetectionCount != 1 {
		t.Fatal(card, e)
	}
	apply := func(c incidents.Command) incidents.Card {
		t.Helper()
		c.ID = card.ID
		c.Version = card.Version
		v, e := s.IncidentCommand(ctx, c, "analyst", now.Add(time.Minute))
		if e != nil {
			t.Fatal(c, e)
		}
		card = v
		return v
	}
	apply(incidents.Command{Action: "comment", Text: "Initial assessment"})
	if _, e = s.IncidentCommand(ctx, incidents.Command{Action: "comment", ID: card.ID, Version: 1, Text: "Stale overwrite"}, "other", now); !errors.Is(e, incidents.ErrConflict) {
		t.Fatal(e)
	}
	if _, e = s.IncidentCommand(ctx, incidents.Command{Action: "transition", ID: card.ID, Version: card.Version, State: "closed", Outcome: "confirmed", Text: "Skip workflow"}, "analyst", now); !errors.Is(e, incidents.ErrConflict) {
		t.Fatal(e)
	}
	apply(incidents.Command{Action: "transition", State: "in_progress", Text: "Taking ownership"})
	apply(incidents.Command{Action: "transition", State: "contained", Text: "Containment confirmed"})
	if _, e = s.IncidentCommand(ctx, incidents.Command{Action: "transition", ID: card.ID, Version: card.Version, State: "resolved", Text: "Missing classification"}, "analyst", now); !errors.Is(e, incidents.ErrInvalid) {
		t.Fatal(e)
	}
	apply(incidents.Command{Action: "transition", State: "resolved", Outcome: "confirmed", Text: "Resolution recorded"})
	apply(incidents.Command{Action: "transition", State: "closed", Outcome: "confirmed", Text: "Closure review complete"})
	if card.Resolution != "Closure review complete" || card.State != "closed" {
		t.Fatal(card)
	}
	if _, e = s.IncidentCommand(ctx, incidents.Command{Action: "comment", ID: card.ID, Version: card.Version, Text: "Modify closed"}, "analyst", now); !errors.Is(e, incidents.ErrConflict) {
		t.Fatal(e)
	}
	apply(incidents.Command{Action: "transition", State: "in_progress", Text: "Reopened after new evidence"})
	if card.Resolution != "" || card.Outcome != "" {
		t.Fatal("old outcome remained current", card)
	}
	apply(incidents.Command{Action: "unlink", DetectionID: d.ID, Text: "Linked to wrong case"})
	if card.DetectionCount != 0 {
		t.Fatal(card)
	}
	apply(incidents.Command{Action: "link", DetectionID: d.ID})
	if card.DetectionCount != 1 {
		t.Fatal(card)
	}
	history, e := s.IncidentHistory(ctx, card.ID, 0, 101)
	if e != nil || len(history) != card.Version {
		t.Fatal(history, e)
	}
	found := false
	for _, h := range history {
		if h.Kind == "transition" && h.Text == "resolved → closed · confirmed\nClosure review complete" {
			found = true
		}
		if h.Actor != "analyst" {
			t.Fatal(h)
		}
	}
	if !found {
		t.Fatal("closure history lost")
	}
	links, e := s.IncidentDetections(ctx, card.ID, 0, 101)
	if e != nil || len(links) != 1 || links[0].ID != d.ID {
		t.Fatal(links, e)
	}
	if _, e = s.ReadRaw(ctx, d.Evidence[0]); e != nil {
		t.Fatal("evidence deleted", e)
	}
}
func TestIncidentAuditFailureRollsBackAndMigratesV1(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "events.db")
	s, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.ExecContext(ctx, `DROP TABLE incident_history;DROP TABLE incident_detections;DROP TABLE incidents;PRAGMA user_version=1;`); e != nil {
		t.Fatal(e)
	}
	a := telemetry.ID("a")
	if _, e = s.Accept(ctx, a, "asset", batch(t, a, 0, "audit")); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var version int
	s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version)
	if version != 2 {
		t.Fatal(version)
	}
	status, _ := s.Status(ctx)
	if status.Raw != 1 {
		t.Fatal("event history lost")
	}
	_, e = s.db.ExecContext(ctx, `CREATE TRIGGER reject_incident_history BEFORE INSERT ON incident_history BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END`)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.IncidentCommand(ctx, incidents.Command{Action: "create", Title: "Rollback", Severity: "medium"}, "analyst", time.Now()); e == nil {
		t.Fatal("expected audit failure")
	}
	cards, e := s.Incidents(ctx, 0, "", "", "", 101)
	if e != nil || len(cards) != 0 {
		t.Fatal("orphan incident", cards, e)
	}
}
