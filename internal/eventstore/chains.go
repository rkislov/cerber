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

var chainIndexes = map[string]string{
	"normalized_chain_account": `CREATE INDEX IF NOT EXISTS normalized_chain_account ON normalized_events(json_extract(payload,'$.identity.account_key'),event_time,sequence) WHERE json_extract(payload,'$.identity.account_key') IS NOT NULL`,
	"normalized_chain_guid":    `CREATE INDEX IF NOT EXISTS normalized_chain_guid ON normalized_events(json_extract(payload,'$.identity.session_guid'),event_time,sequence) WHERE json_extract(payload,'$.identity.session_guid') IS NOT NULL`,
	"normalized_chain_ssh":     `CREATE INDEX IF NOT EXISTS normalized_chain_ssh ON normalized_events(json_extract(payload,'$.identity.ssh_key'),event_time,sequence) WHERE json_extract(payload,'$.identity.ssh_key') IS NOT NULL`,
	"detection_chain_group":    `CREATE INDEX IF NOT EXISTS detection_chain_group ON detections(rule,json_extract(payload,'$.group_key'),event_time) WHERE rule LIKE 'chain.%'`,
}

func (s *Store) ensureChainIndexes(ctx context.Context) error {
	var present int
	if e := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='index' AND name IN ('normalized_chain_account','normalized_chain_guid','normalized_chain_ssh','detection_chain_group')`).Scan(&present); e != nil {
		return e
	}
	if present == 4 {
		return nil
	}
	if s.path != ":memory:" {
		var ordinal int64
		if e := s.db.QueryRowContext(ctx, "SELECT coalesce(max(sequence),0) FROM normalized_events").Scan(&ordinal); e != nil {
			return e
		}
		if ordinal > 1<<40 {
			return fmt.Errorf("%w: identity index estimate exceeds bound", telemetry.ErrStorageProtected)
		}
		p, e := retentionPolicy(ctx, s.db)
		if e != nil {
			return e
		}
		if e = s.checkWrite(ctx, s.db, p, ordinal*512+(64<<20), true); e != nil {
			return e
		}
	}
	for _, ddl := range chainIndexes {
		if _, e := s.db.ExecContext(ctx, ddl); e != nil {
			return e
		}
	}
	return nil
}
func (r *ruleRuntime) chainHistory(ctx context.Context, tx *sql.Tx, rule string, n telemetry.Normalized) ([]telemetry.Normalized, bool, error) {
	cfg := r.policies[rule].Config
	path, index, value := "account_key", "normalized_chain_account", n.Identity.AccountKey
	if rule == "chain.ssh_key_hosts" {
		path, index, value = "ssh_key", "normalized_chain_ssh", n.Identity.SSHKey
	}
	if rule == "chain.logon_guid_hosts" {
		path, index, value = "session_guid", "normalized_chain_guid", n.Identity.SessionGUID
	}
	// The index is partial and covers only normalized events with explicit identities.
	query := fmt.Sprintf(`SELECT payload FROM normalized_events INDEXED BY %s WHERE json_extract(payload,'$.identity.%s') IS NOT NULL AND json_extract(payload,'$.identity.%s')=? AND event_time>=? AND event_time<=? AND sequence<=? AND status='parsed' ORDER BY event_time DESC,sequence DESC LIMIT 201`, index, path, path)
	from := n.EventTime.Add(-time.Duration(cfg.WindowSeconds) * time.Second)
	rows, e := tx.QueryContext(ctx, query, value, stamp(from.Add(-time.Second)), stamp(n.EventTime.Add(time.Second)), n.Sequence)
	if e != nil {
		return nil, false, e
	}
	// Close the SQLite cursor before fetching memberships from another database.
	candidates := []telemetry.Normalized{}
	truncated := false
	size := 0
	for rows.Next() {
		var p string
		if e = rows.Scan(&p); e != nil {
			break
		}
		size += len(p)
		if len(candidates) >= 200 || size > 8<<20 {
			truncated = true
			break
		}
		var v telemetry.Normalized
		if e = json.Unmarshal([]byte(p), &v); e != nil {
			break
		}
		candidates = append(candidates, v)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return nil, false, e
	}
	out := []telemetry.Normalized{}
	for _, v := range candidates {
		if v.EventTime.Before(from) || v.EventTime.After(n.EventTime) {
			continue
		}
		groups, e := r.groups(ctx, rule, v)
		if e != nil {
			return nil, false, e
		}
		if _, reason := rulepolicy.ScopeEvent(cfg, v.AgentID, v.User, v.SourceIP, v.DestinationIP, groups); reason == "" {
			out = append(out, v)
		}
	}
	return out, truncated, nil
}
func (r *ruleRuntime) evaluateChain(ctx context.Context, tx *sql.Tx, rule string, n telemetry.Normalized) (*telemetry.Detection, string, bool, error) {
	v, ok := r.policies[rule]
	if !ok {
		return nil, "", false, rulepolicy.ErrInvalid
	}
	groups, e := r.groups(ctx, rule, n)
	if e != nil {
		return nil, "", false, e
	}
	matched, reason := rulepolicy.ScopeEvent(v.Config, n.AgentID, n.User, n.SourceIP, n.DestinationIP, groups)
	if reason != "" {
		return nil, reason, false, nil
	}
	eligible := false
	for _, id := range correlation.ChainCandidates(n) {
		eligible = eligible || id == rule
	}
	if !eligible {
		return nil, "Нет подходящего SID, GUID или отпечатка ключа; совпадения имён и локальных ID между узлами не используются", false, nil
	}
	h, truncated, e := r.chainHistory(ctx, tx, rule, n)
	if e != nil {
		return nil, "", false, e
	}
	d := correlation.Chain(rule, n, h, v.Config.Threshold, truncated)
	if d == nil {
		return nil, "Недостаточно различных узлов или нет упорядоченной связи входа и очистки в одном локальном сеансе", truncated, nil
	}
	for j, step := range d.Chain.Steps {
		g, e := r.groups(ctx, rule, telemetry.Normalized{AgentID: step.AgentID})
		if e != nil {
			return nil, "", false, e
		}
		d.Chain.Steps[j].MatchedGroups, _ = rulepolicy.ScopeEvent(v.Config, step.AgentID, step.User, step.SourceIP, "", g)
	}
	d.Policy = rulepolicy.Application(v, matched)
	return d, "", truncated, nil
}
func (r *ruleRuntime) insertDetection(ctx context.Context, tx *sql.Tx, d telemetry.Detection, n telemetry.Normalized) error {
	seconds := r.policies[d.Rule].Config.SuppressionSeconds
	suppressed, e := configuredSuppressed(ctx, tx, d, n, seconds)
	if e != nil || suppressed {
		return e
	}
	p, _ := json.Marshal(d)
	_, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO detections(id,rule,agent_id,user_name,source_ip,event_time,payload) VALUES(?,?,?,?,?,?,?)", d.ID, d.Rule, d.AgentID, d.User, d.SourceIP, stamp(n.EventTime), string(p))
	return e
}
