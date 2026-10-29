// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/correlation"
	"github.com/rkislov/cerber/internal/rulepolicy"
	"github.com/rkislov/cerber/internal/telemetry"
	"time"
)

type RuleGroupSource interface {
	CorrelationAgentGroups(context.Context, string) ([]string, error)
}

func (s *Store) SetRuleGroupSource(v RuleGroupSource) {
	s.policyMu.Lock()
	s.policyGroups = v
	s.policyMu.Unlock()
}

type ruleRuntime struct {
	store    *Store
	policies map[string]rulepolicy.Version
	members  map[string][]string
}

func (r *ruleRuntime) groups(ctx context.Context, rule string, n telemetry.Normalized) ([]string, error) {
	if !r.policies[rule].Config.Enabled || len(r.policies[rule].Config.GroupIDs) == 0 {
		return []string{}, nil
	}
	if v, ok := r.members[n.AgentID]; ok {
		return v, nil
	}
	r.store.policyMu.RLock()
	source := r.store.policyGroups
	r.store.policyMu.RUnlock()
	if source == nil {
		return nil, fmt.Errorf("correlation group source unavailable")
	}
	v, e := source.CorrelationAgentGroups(ctx, n.AgentID)
	if e == nil {
		r.members[n.AgentID] = v
	}
	return v, e
}
func policyHistory(ctx context.Context, tx *sql.Tx, rule string, cfg rulepolicy.Config, n telemetry.Normalized, groups []string) ([]telemetry.Normalized, bool, error) {
	out := []telemetry.Normalized{}
	if cfg.WindowSeconds == 0 {
		return out, false, nil
	}
	from := n.EventTime.Add(-time.Duration(cfg.WindowSeconds) * time.Second)
	args := []any{n.AgentID, stamp(from.Add(-time.Second)), stamp(n.EventTime.Add(time.Second)), n.Sequence}
	query := `SELECT payload FROM normalized_events WHERE agent_id=? AND event_time>=? AND event_time<=? AND sequence<=? AND status='parsed' `
	if n.Class == "authentication" {
		query += `AND class='authentication' AND outcome='failure' AND user_name=? AND source_ip=? `
		args = append(args, n.User, n.SourceIP)
	} else {
		query += `AND class=? AND source_ip=? AND json_extract(payload,'$.product')=? AND coalesce(json_extract(payload,'$.device'),'')=? AND coalesce(json_extract(payload,'$.destination_ip'),'')=? `
		args = append(args, n.Class, n.SourceIP, n.Product, n.Device, n.DestinationIP)
		if rule == "firewall.syn_scan" {
			query += `AND json_extract(payload,'$.action')='syn' `
		} else {
			query += `AND outcome='failure' `
		}
	}
	rows, e := tx.QueryContext(ctx, query+`ORDER BY event_time DESC,sequence DESC LIMIT 101`, args...)
	if e != nil {
		return out, false, e
	}
	defer rows.Close()
	count := 0
	historyBytes := 0
	truncated := false
	for rows.Next() {
		count++
		if count > 100 {
			truncated = true
			break
		}
		var p string
		var v telemetry.Normalized
		if e = rows.Scan(&p); e != nil {
			return out, false, e
		}
		historyBytes += len(p)
		if historyBytes > 8<<20 {
			truncated = true
			break
		}
		if e = json.Unmarshal([]byte(p), &v); e != nil {
			return out, false, e
		}
		if v.AssetID != n.AssetID || v.EventTime.Before(from) || v.EventTime.After(n.EventTime) {
			continue
		}
		if _, reason := rulepolicy.ScopeEvent(cfg, v.AgentID, v.User, v.SourceIP, v.DestinationIP, groups); reason == "" {
			out = append(out, v)
		}
	}
	return out, truncated, rows.Err()
}
func (r *ruleRuntime) evaluate(ctx context.Context, tx *sql.Tx, n telemetry.Normalized) (*telemetry.Detection, string, bool, error) {
	lastReason := "Событие не соответствует типу правила"
	wasTruncated := false
	for _, id := range correlation.CandidateRules(n) {
		v, ok := r.policies[id]
		if !ok {
			return nil, "", false, rulepolicy.ErrInvalid
		}
		groups, e := r.groups(ctx, id, n)
		if e != nil {
			return nil, "", false, e
		}
		matched, reason := rulepolicy.ScopeEvent(v.Config, n.AgentID, n.User, n.SourceIP, n.DestinationIP, groups)
		if reason != "" {
			lastReason = reason
			continue
		}
		history, truncated, e := policyHistory(ctx, tx, id, v.Config, n, groups)
		if e != nil {
			return nil, "", truncated, e
		}
		wasTruncated = wasTruncated || truncated
		lastReason = fmt.Sprintf("Недостаточно подходящих событий или различных портов в окне: записей %d, порог %d", len(history), v.Config.Threshold)
		d := correlation.Configured(id, n, history, v.Config.Threshold)
		if d != nil {
			d.Policy = rulepolicy.Application(v, matched)
			return d, "", truncated, nil
		}
	}
	return nil, lastReason, wasTruncated, nil
}
func configuredSuppressed(ctx context.Context, tx *sql.Tx, d telemetry.Detection, n telemetry.Normalized, seconds int) (bool, error) {
	if seconds == 0 {
		return false, nil
	}
	var count int
	e := tx.QueryRowContext(ctx, `SELECT count(*) FROM detections WHERE rule=? AND agent_id=? AND user_name=? AND source_ip=? AND coalesce(json_extract(payload,'$.group_key'),'')=? AND event_time>=? AND event_time<=?`, d.Rule, d.AgentID, d.User, d.SourceIP, d.GroupKey, stamp(n.EventTime.Add(-time.Duration(seconds)*time.Second)), stamp(n.EventTime.Add(time.Duration(seconds)*time.Second))).Scan(&count)
	return count > 0, e
}
func (r *ruleRuntime) correlate(ctx context.Context, tx *sql.Tx, n telemetry.Normalized) error {
	d, _, _, e := r.evaluate(ctx, tx, n)
	if e != nil || d == nil {
		return e
	}
	suppressed, e := configuredSuppressed(ctx, tx, *d, n, r.policies[d.Rule].Config.SuppressionSeconds)
	if e != nil || suppressed {
		return e
	}
	p, _ := json.Marshal(d)
	_, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO detections(id,rule,agent_id,user_name,source_ip,event_time,payload) VALUES(?,?,?,?,?,?,?)", d.ID, d.Rule, d.AgentID, d.User, d.SourceIP, stamp(n.EventTime), string(p))
	return e
}
