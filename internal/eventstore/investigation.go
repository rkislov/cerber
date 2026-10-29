// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/cerber/internal/attack"
	"github.com/rkislov/cerber/internal/correlation"
	"github.com/rkislov/cerber/internal/incidents"
	"github.com/rkislov/cerber/internal/telemetry"
	"sort"
	"time"
)

func investigationDetection(row interface{ Scan(...any) error }) (telemetry.Detection, error) {
	var d telemetry.Detection
	var p string
	e := row.Scan(&d.Sequence, &p, &d.State, &d.AcknowledgedBy)
	if errors.Is(e, sql.ErrNoRows) {
		return d, incidents.ErrNotFound
	}
	if e != nil {
		return d, e
	}
	seq, state, by := d.Sequence, d.State, d.AcknowledgedBy
	e = json.Unmarshal([]byte(p), &d)
	d.Sequence, d.State, d.AcknowledgedBy = seq, state, by
	d.Attack = attack.RuleVersion(d.Rule, d.Version)
	return d, e
}

// Investigation reads a consistent bounded snapshot. No detections, incidents,
// response actions or severities are created or modified by this operation.
func (s *Store) Investigation(ctx context.Context, incidentID, detectionID string) (correlation.Investigation, error) {
	out := correlation.Investigation{At: time.Now().UTC(), WindowSeconds: int(correlation.InvestigationWindow.Seconds()), Anchors: []telemetry.Detection{}, Related: []correlation.RelatedDetection{}, Hypotheses: []correlation.Hypothesis{}, Limitations: "Это гипотезы для расследования, а не доказательство цепочки атаки. Связь только с исходными опорными срабатываниями: одинаковые агент/актив и общий исходник, имя пользователя либо IP в пределах ±30 минут. Исторические срабатывания могут ссылаться на явно удалённые исходники. Список ограничен; отсутствие связи не доказывает отсутствие активности. Active response автоматически не запускается."}
	if incidentID != "" && detectionID != "" || incidentID == "" && detectionID == "" || incidentID != "" && !telemetry.Identifier(incidentID) || detectionID != "" && !telemetry.Identifier(detectionID) {
		return out, incidents.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if e := s.ensureInvestigationIndex(ctx); e != nil {
		return out, e
	}
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	linked := map[string]bool{}
	if incidentID != "" {
		c, e := scanIncident(tx.QueryRowContext(ctx, incidentSelect+"WHERE i.id=?", incidentID))
		if e != nil {
			return out, e
		}
		out.IncidentID = c.ID
		out.IncidentVersion = c.Version
		rows, e := tx.QueryContext(ctx, `SELECT d.sequence,d.payload,d.state,d.acknowledged_by FROM incident_detections l JOIN detections d ON d.id=l.detection_id WHERE l.incident_id=? ORDER BY d.event_time DESC,d.sequence DESC LIMIT 21`, incidentID)
		if e != nil {
			return out, e
		}
		for rows.Next() {
			d, err := investigationDetection(rows)
			if err != nil {
				rows.Close()
				return out, err
			}
			out.Anchors = append(out.Anchors, d)
			linked[d.ID] = true
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, e
		}
		if len(out.Anchors) > 20 {
			out.Truncated = true
			out.Anchors = out.Anchors[:20]
		}
	} else {
		d, e := investigationDetection(tx.QueryRowContext(ctx, "SELECT sequence,payload,state,acknowledged_by FROM detections WHERE id=?", detectionID))
		if e != nil {
			return out, e
		}
		out.Anchors = append(out.Anchors, d)
		linked[d.ID] = true
	}
	// Track every existing incident link so older linked records never become suggestions.
	if incidentID != "" {
		rows, e := tx.QueryContext(ctx, "SELECT detection_id FROM incident_detections WHERE incident_id=?", incidentID)
		if e != nil {
			return out, e
		}
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				break
			}
			linked[id] = true
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return out, e
		}
	}
	candidates := map[string]correlation.RelatedDetection{}
	all := map[string]telemetry.Detection{}
	for _, anchor := range out.Anchors {
		all[anchor.ID] = anchor
		if anchor.AgentID == "" || anchor.AssetID == "" || anchor.LastSeen.IsZero() {
			continue
		}
		// Widen textual bounds by a second, then enforce exact event times in Go.
		rows, e := tx.QueryContext(ctx, `SELECT sequence,payload,state,acknowledged_by FROM detections INDEXED BY detection_investigation_agent_time WHERE agent_id=? AND event_time>=? AND event_time<=? ORDER BY event_time DESC,sequence DESC LIMIT 201`, anchor.AgentID, stamp(anchor.LastSeen.Add(-correlation.InvestigationWindow-time.Second)), stamp(anchor.LastSeen.Add(correlation.InvestigationWindow+time.Second)))
		if e != nil {
			return out, e
		}
		count := 0
		for rows.Next() {
			count++
			if count > 200 {
				out.Truncated = true
				break
			}
			d, e := investigationDetection(rows)
			if e != nil {
				rows.Close()
				return out, e
			}
			if d.ID == anchor.ID {
				continue
			}
			reasons, keys := correlation.RelatedReasons(anchor, d)
			if len(keys) == 0 {
				continue
			}
			item := candidates[d.ID]
			item.AnchorIDs = append(item.AnchorIDs, anchor.ID)
			item.Detection = d
			item.Linked = linked[d.ID]
			seen := map[string]bool{}
			for _, k := range item.Keys {
				seen[k] = true
			}
			for i, k := range keys {
				if !seen[k] {
					item.Keys = append(item.Keys, k)
					item.Reasons = append(item.Reasons, reasons[i])
				}
			}
			candidates[d.ID] = item
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, e
		}
	}
	for _, d := range out.Anchors {
		delete(candidates, d.ID)
	}
	for _, v := range candidates {
		out.Related = append(out.Related, v)
	}
	rank := func(v correlation.RelatedDetection) int {
		for _, k := range v.Keys {
			if k == "same_event" {
				return 0
			}
		}
		for _, k := range v.Keys {
			if k == "same_user" {
				return 1
			}
		}
		return 2
	}
	sort.Slice(out.Related, func(i, j int) bool {
		a, b := out.Related[i], out.Related[j]
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		if a.Detection.LastSeen.Equal(b.Detection.LastSeen) {
			return a.Detection.ID < b.Detection.ID
		}
		return a.Detection.LastSeen.Before(b.Detection.LastSeen)
	})
	if len(out.Related) > correlation.InvestigationLimit {
		out.Truncated = true
		out.Related = out.Related[:correlation.InvestigationLimit]
	}
	for _, v := range out.Related {
		all[v.Detection.ID] = v.Detection
	}
	items := []telemetry.Detection{}
	for _, v := range all {
		items = append(items, v)
	}
	// Every hypothesis must have a direct anchor, without transitive expansion.
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	seenHyp := map[string]bool{}
	for _, a := range out.Anchors {
		for _, b := range items {
			if a.ID == b.ID {
				continue
			}
			for _, h := range correlation.InvestigationHypotheses([]telemetry.Detection{a, b}) {
				if seenHyp[h.ID] {
					continue
				}
				seenHyp[h.ID] = true
				if len(out.Hypotheses) < 20 {
					out.Hypotheses = append(out.Hypotheses, h)
				} else {
					out.Truncated = true
				}
			}
		}
	}

	return out, tx.Commit()
}

func (s *Store) ensureInvestigationIndex(ctx context.Context) error {
	var present int
	if e := s.db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='index' AND name='detection_investigation_agent_time'").Scan(&present); e != nil {
		return e
	}
	if present > 0 {
		return nil
	}
	if s.path != ":memory:" {
		var ordinal int64
		if e := s.db.QueryRowContext(ctx, "SELECT coalesce(max(sequence),0) FROM detections").Scan(&ordinal); e != nil {
			return e
		}
		p, e := retentionPolicy(ctx, s.db)
		if e != nil {
			return e
		}
		if ordinal > 1<<40 {
			return fmt.Errorf("%w: investigation index estimate exceeds bound", telemetry.ErrStorageProtected)
		}
		if e = s.checkWrite(ctx, s.db, p, ordinal*256+(32<<20), false); e != nil {
			return e
		}
	}
	_, e := s.db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS detection_investigation_agent_time ON detections(agent_id,event_time,sequence)")
	return e
}
