// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/cerber/internal/attack"
	"github.com/rkislov/cerber/internal/incidents"
	"github.com/rkislov/cerber/internal/telemetry"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const incidentSelect = `SELECT i.sequence,i.id,i.title,i.description,i.severity,i.state,i.assignee,i.created_by,i.created_at,i.updated_at,i.version,i.resolution,i.outcome,(SELECT count(*) FROM incident_detections d WHERE d.incident_id=i.id) FROM incidents i `

func scanIncident(row interface{ Scan(...any) error }) (incidents.Card, error) {
	var c incidents.Card
	var created, updated string
	e := row.Scan(&c.Sequence, &c.ID, &c.Title, &c.Description, &c.Severity, &c.State, &c.Assignee, &c.CreatedBy, &created, &updated, &c.Version, &c.Resolution, &c.Outcome, &c.DetectionCount)
	if errors.Is(e, sql.ErrNoRows) {
		return c, incidents.ErrNotFound
	}
	if e != nil {
		return c, e
	}
	c.CreatedAt, e = time.Parse(time.RFC3339Nano, created)
	if e != nil {
		return c, e
	}
	c.UpdatedAt, e = time.Parse(time.RFC3339Nano, updated)
	return c, e
}
func (s *Store) Incident(ctx context.Context, id string) (incidents.Card, error) {
	return scanIncident(s.db.QueryRowContext(ctx, incidentSelect+"WHERE i.id=?", id))
}
func (s *Store) Incidents(ctx context.Context, before int64, state, severity, assignee string, limit int) ([]incidents.Card, error) {
	if before < 0 || limit < 1 || limit > 101 || state != "" && !incidents.ValidState(state) || severity != "" && !incidents.ValidSeverity(severity) || len(assignee) > 64 {
		return nil, incidents.ErrInvalid
	}
	rows, e := s.db.QueryContext(ctx, incidentSelect+"WHERE (?=0 OR i.sequence<?) AND (?='' OR i.state=?) AND (?='' OR i.severity=?) AND (?='' OR i.assignee=?) ORDER BY i.sequence DESC LIMIT ?", before, before, state, state, severity, severity, assignee, assignee, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []incidents.Card{}
	for rows.Next() {
		c, e := scanIncident(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func incidentText(s string, max int, multiline bool) bool {
	if !utf8.ValidString(s) || len(s) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && !(multiline && (r == '\n' || r == '\t' || r == '\r')) {
			return false
		}
	}
	return true
}

// IncidentCommand commits one version and its immutable history entry together.
// actor is authenticated by the case-management boundary, never read from request JSON.
func (s *Store) IncidentCommand(ctx context.Context, c incidents.Command, actor string, now time.Time) (incidents.Card, error) {
	var out incidents.Card
	if actor == "" || !incidentText(actor, 64, false) {
		return out, incidents.ErrInvalid
	}
	if c.Outcome != "" && !incidents.ValidOutcome(c.Outcome) {
		return out, incidents.ErrInvalid
	}
	c.Title = strings.TrimSpace(c.Title)
	c.Text = strings.TrimSpace(c.Text)
	switch c.Action {
	case "create", "update":
		if c.Title == "" || !incidentText(c.Title, 256, false) || !incidentText(c.Description, 16384, true) || !incidents.ValidSeverity(c.Severity) || len(c.Assignee) > 64 {
			return out, incidents.ErrInvalid
		}
	case "comment", "transition":
		if c.Text == "" || !incidentText(c.Text, 8192, true) {
			return out, incidents.ErrInvalid
		}
	case "link", "unlink":
		if !telemetry.Identifier(c.DetectionID) || c.Action == "unlink" && (c.Text == "" || !incidentText(c.Text, 8192, true)) {
			return out, incidents.ErrInvalid
		}
	default:
		return out, incidents.ErrInvalid
	}
	if c.Action != "create" && (!telemetry.Identifier(c.ID) || c.Version < 1) {
		return out, incidents.ErrInvalid
	}
	if c.Action == "create" && c.DetectionID != "" && !telemetry.Identifier(c.DetectionID) {
		return out, incidents.ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	var prior incidents.Card
	if c.Action != "create" {
		prior, e = scanIncident(tx.QueryRowContext(ctx, incidentSelect+"WHERE i.id=?", c.ID))
		if e != nil {
			return out, e
		}
		if prior.Version != c.Version {
			return out, incidents.ErrConflict
		}
		if prior.State == "closed" && c.Action != "transition" {
			return out, incidents.ErrConflict
		}
	}
	id := c.ID
	version := c.Version + 1
	entry := c.Text
	link := func() error {
		var n int
		if e := tx.QueryRowContext(ctx, "SELECT count(*) FROM detections WHERE id=?", c.DetectionID).Scan(&n); e != nil {
			return e
		}
		if n == 0 {
			return incidents.ErrNotFound
		}
		if e := tx.QueryRowContext(ctx, "SELECT count(*) FROM incident_detections WHERE incident_id=?", id).Scan(&n); e != nil {
			return e
		}
		var exists int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM incident_detections WHERE incident_id=? AND detection_id=?", id, c.DetectionID).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			return incidents.ErrConflict
		}
		if n >= 1000 {
			return incidents.ErrConflict
		}
		_, e := tx.ExecContext(ctx, "INSERT OR IGNORE INTO incident_detections VALUES(?,?)", id, c.DetectionID)
		return e
	}
	switch c.Action {
	case "create":
		var nonce [32]byte
		if _, e = rand.Read(nonce[:]); e != nil {
			return out, e
		}
		id = hex.EncodeToString(nonce[:])
		version = 1
		_, e = tx.ExecContext(ctx, "INSERT INTO incidents(id,title,description,severity,state,assignee,created_by,created_at,updated_at,version) VALUES(?,?,?,?,?,?,?,?,?,1)", id, c.Title, c.Description, c.Severity, "new", c.Assignee, actor, stamp(now), stamp(now))
		if e == nil && c.DetectionID != "" {
			e = link()
		}
		payload, _ := json.Marshal(map[string]string{"title": c.Title, "description": c.Description, "severity": c.Severity, "assignee": c.Assignee, "detection_id": c.DetectionID})
		entry = string(payload)
	case "update":
		_, e = tx.ExecContext(ctx, "UPDATE incidents SET title=?,description=?,severity=?,assignee=? WHERE id=?", c.Title, c.Description, c.Severity, c.Assignee, id)
		payload, _ := json.Marshal(map[string]string{"title": c.Title, "description": c.Description, "severity": c.Severity, "assignee": c.Assignee})
		entry = string(payload)
	case "transition":
		if !incidents.CanTransition(prior.State, c.State) {
			return out, incidents.ErrConflict
		}
		if (c.State == "resolved" || c.State == "closed") && !incidents.ValidOutcome(c.Outcome) {
			return out, incidents.ErrInvalid
		}
		resolution, outcome := prior.Resolution, prior.Outcome
		if c.State == "resolved" || c.State == "closed" {
			resolution, outcome = c.Text, c.Outcome
		}
		if c.State == "in_progress" && (prior.State == "resolved" || prior.State == "closed") {
			resolution, outcome = "", ""
		}
		_, e = tx.ExecContext(ctx, "UPDATE incidents SET state=?,resolution=?,outcome=? WHERE id=?", c.State, resolution, outcome, id)
		entry = fmt.Sprintf("%s → %s · %s\n%s", prior.State, c.State, c.Outcome, c.Text)
	case "link":
		e = link()
		entry = c.DetectionID
	case "unlink":
		res, err := tx.ExecContext(ctx, "DELETE FROM incident_detections WHERE incident_id=? AND detection_id=?", id, c.DetectionID)
		if err != nil {
			return out, err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return out, incidents.ErrNotFound
		}
		entry = c.DetectionID + "\n" + c.Text
	case "comment":
	}
	if e != nil {
		return out, e
	}
	if c.Action != "create" {
		if _, e = tx.ExecContext(ctx, "UPDATE incidents SET version=?,updated_at=? WHERE id=?", version, stamp(now), id); e != nil {
			return out, e
		}
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO incident_history(incident_id,kind,actor,at,text,version) VALUES(?,?,?,?,?,?)", id, c.Action, actor, stamp(now), entry, version); e != nil {
		return out, e
	}
	out, e = scanIncident(tx.QueryRowContext(ctx, incidentSelect+"WHERE i.id=?", id))
	if e != nil {
		return out, e
	}
	return out, tx.Commit()
}
func (s *Store) IncidentHistory(ctx context.Context, id string, before int64, limit int) ([]incidents.Entry, error) {
	if before < 0 || limit < 1 || limit > 101 {
		return nil, incidents.ErrInvalid
	}
	rows, e := s.db.QueryContext(ctx, "SELECT sequence,kind,actor,at,text,version FROM incident_history WHERE incident_id=? AND (?=0 OR sequence<?) ORDER BY sequence DESC LIMIT ?", id, before, before, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []incidents.Entry{}
	for rows.Next() {
		var v incidents.Entry
		var at string
		if e = rows.Scan(&v.Sequence, &v.Kind, &v.Actor, &at, &v.Text, &v.Version); e != nil {
			return nil, e
		}
		v.At, e = time.Parse(time.RFC3339Nano, at)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) IncidentDetections(ctx context.Context, id string, before int64, limit int) ([]telemetry.Detection, error) {
	if before < 0 || limit < 1 || limit > 101 {
		return nil, incidents.ErrInvalid
	}
	rows, e := s.db.QueryContext(ctx, "SELECT d.sequence,d.payload,d.state,d.acknowledged_by FROM incident_detections l JOIN detections d ON d.id=l.detection_id WHERE l.incident_id=? AND (?=0 OR d.sequence<?) ORDER BY d.sequence DESC LIMIT ?", id, before, before, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []telemetry.Detection{}
	for rows.Next() {
		var d telemetry.Detection
		var seq int64
		var p, state, by string
		if e = rows.Scan(&seq, &p, &state, &by); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(p), &d); e != nil {
			return nil, e
		}
		d.Sequence, d.State, d.AcknowledgedBy = seq, state, by
		d.Attack = attack.RuleVersion(d.Rule, d.Version)
		out = append(out, d)
	}
	return out, rows.Err()
}
