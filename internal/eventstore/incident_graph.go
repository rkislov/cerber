// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/correlation"
	"github.com/rkislov/cerber/internal/incidents"
	"github.com/rkislov/cerber/internal/telemetry"
	"time"
)

// IncidentGraph reads only chains explicitly linked to the case. It performs no
// neighborhood discovery, vulnerability enrichment, writes or cursor changes.
func (s *Store) IncidentGraph(ctx context.Context, id string) (correlation.Investigation, error) {
	out := correlation.Investigation{IncidentID: id, At: time.Now().UTC(), Anchors: []telemetry.Detection{}, Related: []correlation.RelatedDetection{}, Hypotheses: []correlation.Hypothesis{}}
	if !telemetry.Identifier(id) {
		return out, incidents.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	e = tx.QueryRowContext(ctx, "SELECT version FROM incidents WHERE id=?", id).Scan(&out.IncidentVersion)
	if errors.Is(e, sql.ErrNoRows) {
		return out, incidents.ErrNotFound
	}
	if e != nil {
		return out, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT d.sequence,d.payload,d.state,d.acknowledged_by FROM incident_detections l JOIN detections d ON d.id=l.detection_id WHERE l.incident_id=? AND json_extract(d.payload,'$.chain.version') IN (1,2) ORDER BY d.event_time DESC,d.sequence DESC LIMIT 21`, id)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	size := 0
	for rows.Next() {
		var d telemetry.Detection
		var p string
		if e = rows.Scan(&d.Sequence, &p, &d.State, &d.AcknowledgedBy); e != nil {
			return out, e
		}
		size += len(p)
		if len(out.Anchors) >= 20 || size > 4<<20 {
			out.Truncated = true
			break
		}
		seq, state, by := d.Sequence, d.State, d.AcknowledgedBy
		if e = json.Unmarshal([]byte(p), &d); e != nil {
			return out, e
		}
		d.Sequence, d.State, d.AcknowledgedBy = seq, state, by
		out.Anchors = append(out.Anchors, d)
	}
	if e = rows.Err(); e != nil {
		return out, e
	}
	rows.Close()
	for i := range out.Anchors {
		c := out.Anchors[i].Chain
		if c == nil {
			continue
		}
		truncated, err := activityContext(ctx, tx, c)
		if err != nil {
			return out, err
		}
		if err = serviceConfirmations(ctx, tx, c); err != nil {
			return out, err
		}
		out.Truncated = out.Truncated || truncated || c.Truncated
		c.Limitations += " Контекст процессов/служб/заданий добавлен на момент открытия графа из оперативного журнала; до 20 шагов, окно 30 минут. 7045 не содержит SID/сеанса инициатора и автоматически к пользователю не привязывается."
	}
	return out, tx.Commit()
}
