// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/rkislov/cerber/internal/integrations"
	"github.com/rkislov/cerber/internal/rulepolicy"
	"github.com/rkislov/cerber/internal/telemetry"
)

// ScanIOC commits detections and cursor together; a new feed revision rechecks retained events.
func (s *Store) ScanIOC(ctx context.Context, index *integrations.Index, revision string) error {
	if index == nil {
		return nil
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	_, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO consumer_cursors(name,position) VALUES('threatfox/1',0)")
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS threatfox_revision(value TEXT NOT NULL)")
	if e != nil {
		return e
	}
	var old string
	e = tx.QueryRowContext(ctx, "SELECT value FROM threatfox_revision LIMIT 1").Scan(&old)
	if e != nil && e != sql.ErrNoRows {
		return e
	}
	if old != revision {
		if _, e = tx.ExecContext(ctx, "DELETE FROM threatfox_revision;UPDATE consumer_cursors SET position=0 WHERE name='threatfox/1'"); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO threatfox_revision(value) VALUES(?)", revision); e != nil {
			return e
		}
	}
	rows, e := tx.QueryContext(ctx, "SELECT sequence,payload FROM normalized_events WHERE sequence>(SELECT position FROM consumer_cursors WHERE name='threatfox/1') ORDER BY sequence LIMIT 200")
	if e != nil {
		return e
	}
	var events []telemetry.Normalized
	var cursor int64
	for rows.Next() {
		var p string
		var seq int64
		if e = rows.Scan(&seq, &p); e != nil {
			rows.Close()
			return e
		}
		var n telemetry.Normalized
		if e = json.Unmarshal([]byte(p), &n); e != nil {
			rows.Close()
			return e
		}
		cursor = seq
		events = append(events, n)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	policies, e := loadRulePolicies(ctx, tx)
	if e != nil {
		return e
	}
	runtime := ruleRuntime{store: s, policies: policies, members: map[string][]string{}}
	for _, n := range events {
		for _, d := range index.Match(n) {
			v, ok := policies[d.Rule]
			if !ok {
				return rulepolicy.ErrInvalid
			}
			groups, e := runtime.groups(ctx, d.Rule, n)
			if e != nil {
				return e
			}
			matched, reason := rulepolicy.ScopeEvent(v.Config, n.AgentID, n.User, n.SourceIP, n.DestinationIP, groups)
			if reason != "" {
				continue
			}
			d.Policy = rulepolicy.Application(v, matched)
			p, _ := json.Marshal(d)
			if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO detections(id,rule,agent_id,user_name,source_ip,event_time,payload) VALUES(?,?,?,?,?,?,?)", d.ID, d.Rule, d.AgentID, d.User, d.SourceIP, stamp(n.EventTime), string(p)); e != nil {
				return e
			}
		}
	}
	if cursor > 0 {
		_, e = tx.ExecContext(ctx, "UPDATE consumer_cursors SET position=? WHERE name='threatfox/1'", cursor)
		if e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Store) NotificationBatch(ctx context.Context, after int64) ([]integrations.Notification, error) {
	rows, e := s.db.QueryContext(ctx, "SELECT sequence,id,payload FROM detections WHERE sequence>? AND state='open' ORDER BY sequence LIMIT 100", after)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []integrations.Notification{}
	for rows.Next() {
		var n integrations.Notification
		var p string
		if e = rows.Scan(&n.Sequence, &n.ID, &p); e != nil {
			return nil, e
		}
		var d telemetry.Detection
		if e = json.Unmarshal([]byte(p), &d); e != nil {
			return nil, e
		}
		n.Subject = "Срабатывание SIEM: " + d.Rule
		n.Body = d.Title + "\nАгент: " + d.AgentID + "\nID срабатывания: " + d.ID
		n.Details = integrations.MailDetails{Title: d.Title, Kind: "detection", Severity: d.Severity, OccurredAt: d.CreatedAt,
			Fields: []integrations.MailField{
				{Label: "Правило", Value: d.Rule},
				{Label: "IP источника", Value: d.SourceIP},
				{Label: "Учётная запись", Value: d.User},
				{Label: "Агент", Value: d.AgentID, Code: true},
				{Label: "ID срабатывания", Value: d.ID, Code: true},
			}}
		if d.ObserverOnly {
			n.Details.Summary = "Сетевое наблюдение. Само по себе не подтверждает компрометацию узла."
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
