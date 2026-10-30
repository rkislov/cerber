// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/attack"
	"github.com/rkislov/cerber/internal/telemetry"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

func (s *Store) ReadEvents(ctx context.Context, q telemetry.Query) ([]telemetry.Normalized, error) {
	if q.Before < 0 || q.Limit < 1 || q.Limit > 101 || q.AgentID != "" && !telemetry.AgentIdentifier(q.AgentID) || q.Class != "" && q.Class != "network_connection" && q.Class != "process" && q.Class != "service" && q.Class != "task" && q.Class != "session" && q.Class != "firewall" && q.Class != "fess" && q.Class != "kerberos" && q.Class != "credentials" && q.Class != "authentication" && q.Class != "audit" && q.Class != "system" && q.Class != "unknown" || q.Status != "" && q.Status != "parsed" && q.Status != "quarantine" {
		return nil, telemetry.ErrInvalid
	}
	if q.TimeField != "" && q.TimeField != "event" && q.TimeField != "received" {
		return nil, telemetry.ErrInvalid
	}
	if !queryText(q.Text, 1024) || !queryText(q.User, 2048) || !queryText(q.Code, 64) || q.Source != "" && !telemetry.ValidSource(q.Source) || q.Outcome != "" && q.Outcome != "success" && q.Outcome != "failure" && q.Outcome != "unknown" {
		return nil, telemetry.ErrInvalid
	}
	if q.SourceIP != "" {
		ip, e := netip.ParseAddr(q.SourceIP)
		if e != nil {
			return nil, telemetry.ErrInvalid
		}
		q.SourceIP = ip.Unmap().String()
	}
	q.User = strings.ToLower(q.User)
	if q.From != nil && q.Until != nil && !q.From.Before(*q.Until) {
		return nil, telemetry.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	sqlQuery := "SELECT n.payload FROM normalized_events n"
	timeColumn := "n.event_time"
	if q.TimeField == "received" {
		sqlQuery += " JOIN raw_events r ON r.sequence=n.sequence"
		timeColumn = "r.received_at"
	}
	conditions := []string{}
	args := []any{}
	if q.Before > 0 {
		conditions = append(conditions, "n.sequence<?")
		args = append(args, q.Before)
	}
	for _, field := range []struct{ column, value string }{{"n.agent_id", q.AgentID}, {"n.class", q.Class}, {"n.status", q.Status}, {"json_extract(n.payload,'$.source')", q.Source}, {"n.user_name", q.User}, {"n.source_ip", q.SourceIP}, {"json_extract(n.payload,'$.code')", q.Code}, {"n.outcome", q.Outcome}} {
		if field.value != "" {
			conditions = append(conditions, field.column+"=?")
			args = append(args, field.value)
		}
	}
	if q.From != nil {
		conditions = append(conditions, timeColumn+">=?")
		args = append(args, stamp(*q.From))
	}
	if q.Until != nil {
		conditions = append(conditions, timeColumn+"<?")
		args = append(args, stamp(*q.Until))
	}
	if strings.TrimSpace(q.Text) != "" {
		conditions = append(conditions, "n.sequence IN (SELECT rowid FROM event_search WHERE event_search MATCH ?)")
		args = append(args, `"`+strings.ReplaceAll(strings.TrimSpace(q.Text), `"`, `""`)+`"`)
	}
	if len(conditions) > 0 {
		sqlQuery += " WHERE " + strings.Join(conditions, " AND ")
	}
	sqlQuery += " ORDER BY n.sequence DESC LIMIT ?"
	args = append(args, q.Limit)
	rows, e := s.db.QueryContext(ctx, sqlQuery, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []telemetry.Normalized{}
	for rows.Next() {
		var p string
		var n telemetry.Normalized
		if e = rows.Scan(&p); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(p), &n); e != nil {
			return nil, e
		}
		n.Attack = attack.Event(n.Class, n.Action, n.Outcome, n.Status)
		out = append(out, n)
	}
	return out, rows.Err()
}
func (s *Store) ReadRaw(ctx context.Context, id string) (telemetry.RawRecord, error) {
	var r telemetry.RawRecord
	var at, p string
	e := s.db.QueryRowContext(ctx, "SELECT sequence,agent_id,asset_id,received_at,payload FROM raw_events WHERE id=?", id).Scan(&r.Sequence, &r.AgentID, &r.AssetID, &at, &p)
	if errors.Is(e, sql.ErrNoRows) {
		return s.readArchivedRaw(ctx, id)
	}
	if e != nil {
		return r, e
	}
	r.ReceivedAt, e = time.Parse(time.RFC3339Nano, at)
	if e != nil {
		return r, e
	}
	e = json.Unmarshal([]byte(p), &r.Raw)
	return r, e
}
func (s *Store) ReadDetections(ctx context.Context, before int64, limit int) ([]telemetry.Detection, error) {
	if before < 0 || limit < 1 || limit > 101 {
		return nil, telemetry.ErrInvalid
	}
	rows, e := s.db.QueryContext(ctx, "SELECT sequence,payload,state,acknowledged_by FROM detections WHERE (?=0 OR sequence<?) ORDER BY sequence DESC LIMIT ?", before, before, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []telemetry.Detection{}
	for rows.Next() {
		var d telemetry.Detection
		var p, state, by string
		var seq int64
		if e = rows.Scan(&seq, &p, &state, &by); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(p), &d); e != nil {
			return nil, e
		}
		d.Sequence = seq
		d.State = state
		d.AcknowledgedBy = by
		d.Attack = attack.RuleVersion(d.Rule, d.Version)
		out = append(out, d)
	}
	return out, rows.Err()
}
func (s *Store) Acknowledge(ctx context.Context, id, actor string) error {
	if !telemetry.Identifier(id) || actor == "" {
		return telemetry.ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	res, e := tx.ExecContext(ctx, "UPDATE detections SET state='acknowledged',acknowledged_by=? WHERE id=? AND state='open'", actor, id)
	if e != nil {
		return e
	}
	count, _ := res.RowsAffected()
	if count > 0 {
		if _, e = tx.ExecContext(ctx, "INSERT INTO detection_audit(detection_id,actor,at) VALUES(?,?,?)", id, actor, stamp(time.Now())); e != nil {
			return e
		}
	} else {
		var n int
		if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM detections WHERE id=?", id).Scan(&n); e != nil {
			return e
		}
		if n == 0 {
			return telemetry.ErrNotFound
		}
	}
	return tx.Commit()
}
func (s *Store) Status(ctx context.Context) (telemetry.PipelineStatus, error) {
	var v telemetry.PipelineStatus
	e := s.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM raw_events),(SELECT count(*) FROM normalized_events),(SELECT count(*) FROM normalized_events WHERE status='quarantine'),(SELECT count(*) FROM detections),(SELECT position FROM consumer_cursors WHERE name='normalizer/1'),(SELECT position FROM consumer_cursors WHERE name='correlator/1')`).Scan(&v.Raw, &v.Normalized, &v.Quarantined, &v.Detections, &v.ProcessorCursor, &v.CorrelatorCursor)
	return v, e
}

func queryText(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
