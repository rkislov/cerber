// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/event"
	"time"
)

func (s *Store) EvaluateAlerts(ctx context.Context, now time.Time, policy alerts.Policy) (alerts.Result, error) {
	var result alerts.Result
	if err := policy.Validate(); err != nil {
		return result, err
	}
	if now.IsZero() {
		return result, fmt.Errorf("evaluation time required")
	}
	after := ""
	for {
		page, err := s.evaluateAlertPage(ctx, now, policy, after)
		if err != nil {
			return result, err
		}
		result.Scanned += page.result.Scanned
		result.Raised += page.result.Raised
		result.Resolved += page.result.Resolved
		if page.after == "" {
			return result, nil
		}
		after = page.after
	}
}

type evaluatedPage struct {
	result alerts.Result
	after  string
}

func (s *Store) evaluateAlertPage(ctx context.Context, now time.Time, policy alerts.Policy, after string) (evaluatedPage, error) {
	var page evaluatedPage
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	agents, err := agentStatuses(ctx, tx, "", after, 100)
	if err != nil {
		return page, err
	}
	for _, agent := range agents {
		conditions := alerts.Conditions(agent, now, policy)
		for _, kind := range []string{"agent_offline", "inventory_stale"} {
			var id string
			err = tx.QueryRowContext(ctx, "SELECT id FROM alerts WHERE agent_id=? AND kind=? AND resolved_at IS NULL", agent.AgentID, kind).Scan(&id)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return page, err
			}
			evidence, active := conditions[kind]
			if id == "" && active {
				id, err = domain.NewID()
				if err != nil {
					return page, err
				}
				severity := "warning"
				if kind == "agent_offline" {
					severity = "critical"
				}
				payload, _ := json.Marshal(evidence)
				if _, err = tx.ExecContext(ctx, "INSERT INTO alerts(id,agent_id,asset_id,kind,severity,raised_at,evidence) VALUES(?,?,?,?,?,?,?)", id, agent.AgentID, agent.AssetID, kind, severity, stamp(now), string(payload)); err != nil {
					return page, err
				}
				e, err := event.New("alert.raised", agent.AssetID, map[string]any{"alert_id": id, "agent_id": agent.AgentID, "asset_id": agent.AssetID, "kind": kind, "severity": severity, "raised_at": now, "evidence": evidence})
				if err != nil {
					return page, err
				}
				if err = appendEvent(ctx, tx, e); err != nil {
					return page, err
				}
				page.result.Raised++
			} else if id != "" && !active {
				reason := "condition_cleared"
				if agent.Revoked {
					reason = "agent_revoked"
				}
				if _, err = tx.ExecContext(ctx, "UPDATE alerts SET resolved_at=?,resolution=? WHERE id=?", stamp(now), reason, id); err != nil {
					return page, err
				}
				e, err := event.New("alert.resolved", agent.AssetID, map[string]any{"alert_id": id, "agent_id": agent.AgentID, "kind": kind, "resolved_at": now, "reason": reason})
				if err != nil {
					return page, err
				}
				if err = appendEvent(ctx, tx, e); err != nil {
					return page, err
				}
				page.result.Resolved++
			}
		}
		page.result.Scanned++
	}
	if len(agents) == 100 {
		page.after = agents[len(agents)-1].AgentID
	}
	return page, tx.Commit()
}

const alertSelect = `SELECT a.sequence,a.id,a.agent_id,a.asset_id,x.name,x.ip,a.kind,a.severity,a.raised_at,a.resolved_at,a.resolution,a.acknowledged_at,a.acknowledged_by,a.evidence FROM alerts a JOIN assets x ON x.id=a.asset_id `

func scanAlert(row rowScanner) (alerts.Alert, error) {
	var v alerts.Alert
	var raised, evidence string
	var resolved, resolution, acked, actor sql.NullString
	err := row.Scan(&v.Sequence, &v.ID, &v.AgentID, &v.AssetID, &v.AssetName, &v.AssetIP, &v.Kind, &v.Severity, &raised, &resolved, &resolution, &acked, &actor, &evidence)
	if err != nil {
		return v, err
	}
	if v.RaisedAt, err = parse(raised); err != nil {
		return v, err
	}
	if resolved.Valid {
		at, e := parse(resolved.String)
		if e != nil {
			return v, e
		}
		v.ResolvedAt = &at
	}
	if acked.Valid {
		at, e := parse(acked.String)
		if e != nil {
			return v, e
		}
		v.AcknowledgedAt = &at
	}
	v.Resolution = resolution.String
	v.AcknowledgedBy = actor.String
	err = json.Unmarshal([]byte(evidence), &v.Evidence)
	return v, err
}
func (s *Store) Alerts(ctx context.Context, state string, before int64, limit int) ([]alerts.Alert, error) {
	if state != "active" && state != "resolved" && state != "all" {
		return nil, fmt.Errorf("invalid alert state")
	}
	if before < 0 || limit < 1 || limit > 1001 {
		return nil, fmt.Errorf("invalid alert pagination")
	}
	rows, err := s.db.QueryContext(ctx, alertSelect+`WHERE (?=0 OR a.sequence<?) AND (?='all' OR ?='active' AND a.resolved_at IS NULL OR ?='resolved' AND a.resolved_at IS NOT NULL) ORDER BY a.sequence DESC LIMIT ?`, before, before, state, state, state, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []alerts.Alert{}
	for rows.Next() {
		v, e := scanAlert(rows)
		if e != nil {
			return nil, e
		}
		result = append(result, v)
	}
	return result, rows.Err()
}
func (s *Store) AcknowledgeAlert(ctx context.Context, id, actor string) (alerts.Alert, error) {
	var empty alerts.Alert
	if id == "" || len(id) > 256 || len(actor) > 64 {
		return empty, fmt.Errorf("invalid acknowledgement")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err = checkAdmin(ctx, tx, false); err != nil {
		return empty, err
	}
	v, err := scanAlert(tx.QueryRowContext(ctx, alertSelect+"WHERE a.id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return v, domain.ErrNotFound
	}
	if err != nil {
		return v, err
	}
	if v.AcknowledgedAt != nil {
		return v, nil
	}
	if v.ResolvedAt != nil {
		return v, domain.ErrConflict
	}
	now := time.Now().UTC()
	if _, err = tx.ExecContext(ctx, "UPDATE alerts SET acknowledged_at=?,acknowledged_by=? WHERE id=?", stamp(now), actor, id); err != nil {
		return v, err
	}
	e, err := event.New("alert.acknowledged", v.AssetID, map[string]any{"alert_id": id, "agent_id": v.AgentID, "acknowledged_at": now, "actor": actor})
	if err != nil {
		return v, err
	}
	if err = appendEvent(ctx, tx, e); err != nil {
		return v, err
	}
	v.AcknowledgedAt = &now
	v.AcknowledgedBy = actor
	return v, tx.Commit()
}
