// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/telemetry"
	"time"
)

func (s *Store) ReadEvents(ctx context.Context, q telemetry.Query) ([]telemetry.Normalized, error) {
	if q.Before < 0 || q.Limit < 1 || q.Limit > 101 || q.AgentID != "" && !telemetry.AgentIdentifier(q.AgentID) || q.Class != "" && q.Class != "authentication" && q.Class != "audit" && q.Class != "system" && q.Class != "unknown" || q.Status != "" && q.Status != "parsed" && q.Status != "quarantine" {
		return nil, telemetry.ErrInvalid
	}
	rows, e := s.db.QueryContext(ctx, "SELECT payload FROM normalized_events WHERE (?=0 OR sequence<?) AND (?='' OR agent_id=?) AND (?='' OR class=?) AND (?='' OR status=?) ORDER BY sequence DESC LIMIT ?", q.Before, q.Before, q.AgentID, q.AgentID, q.Class, q.Class, q.Status, q.Status, q.Limit)
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
		out = append(out, n)
	}
	return out, rows.Err()
}
func (s *Store) ReadRaw(ctx context.Context, id string) (telemetry.RawRecord, error) {
	var r telemetry.RawRecord
	var at, p string
	e := s.db.QueryRowContext(ctx, "SELECT sequence,agent_id,asset_id,received_at,payload FROM raw_events WHERE id=?", id).Scan(&r.Sequence, &r.AgentID, &r.AssetID, &at, &p)
	if errors.Is(e, sql.ErrNoRows) {
		return r, telemetry.ErrNotFound
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
