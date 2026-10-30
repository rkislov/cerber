// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/rulepolicy"
	"sort"
	"strings"
	"time"
)

func (s *Store) initRulePolicies(ctx context.Context) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	_, e = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS correlation_policy_versions(rule TEXT NOT NULL,revision INTEGER NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(rule,revision));CREATE TABLE IF NOT EXISTS correlation_policy_active(rule TEXT PRIMARY KEY,revision INTEGER NOT NULL,FOREIGN KEY(rule,revision) REFERENCES correlation_policy_versions(rule,revision));CREATE TABLE IF NOT EXISTS correlation_chain_policy_versions(rule TEXT NOT NULL,revision INTEGER NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(rule,revision));CREATE TABLE IF NOT EXISTS correlation_chain_policy_active(rule TEXT PRIMARY KEY,revision INTEGER NOT NULL,FOREIGN KEY(rule,revision) REFERENCES correlation_chain_policy_versions(rule,revision));CREATE TABLE IF NOT EXISTS correlation_windows_policy_versions(rule TEXT NOT NULL,revision INTEGER NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(rule,revision));CREATE TABLE IF NOT EXISTS correlation_windows_policy_active(rule TEXT PRIMARY KEY,revision INTEGER NOT NULL,FOREIGN KEY(rule,revision) REFERENCES correlation_windows_policy_versions(rule,revision));`)
	if e != nil {
		return e
	}
	for id, cfg := range rulepolicy.Defaults() {
		v := rulepolicy.Version{Rule: id, Revision: 1, Config: cfg, Actor: "system", At: time.Now().UTC(), Reason: "Исходные встроенные условия"}
		p, _ := json.Marshal(v)
		versions, active := policyTables(id)
		if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO "+versions+" VALUES(?,?,?)", id, 1, string(p)); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO "+active+" VALUES(?,1)", id); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func loadRulePolicies(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (map[string]rulepolicy.Version, error) {
	rows, e := q.QueryContext(ctx, "SELECT v.payload FROM correlation_policy_active a JOIN correlation_policy_versions v ON v.rule=a.rule AND v.revision=a.revision UNION ALL SELECT v.payload FROM correlation_chain_policy_active a JOIN correlation_chain_policy_versions v ON v.rule=a.rule AND v.revision=a.revision UNION ALL SELECT v.payload FROM correlation_windows_policy_active a JOIN correlation_windows_policy_versions v ON v.rule=a.rule AND v.revision=a.revision")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]rulepolicy.Version{}
	for rows.Next() {
		var p string
		var v rulepolicy.Version
		if e = rows.Scan(&p); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(p), &v); e != nil {
			return nil, e
		}
		out[v.Rule] = v
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	if len(out) != len(rulepolicy.Defaults()) {
		return nil, rulepolicy.ErrInvalid
	}
	return out, nil
}
func (s *Store) RulePolicies(ctx context.Context) ([]rulepolicy.Version, error) {
	m, e := loadRulePolicies(ctx, s.db)
	out := []rulepolicy.Version{}
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out, e
}
func (s *Store) RulePolicyHistory(ctx context.Context, id string, before int64) ([]rulepolicy.Version, error) {
	if _, ok := rulepolicy.Defaults()[id]; !ok || before < 0 {
		return nil, rulepolicy.ErrInvalid
	}
	versions, _ := policyTables(id)
	rows, e := s.db.QueryContext(ctx, "SELECT payload FROM "+versions+" WHERE rule=? AND (?=0 OR revision<?) ORDER BY revision DESC LIMIT 51", id, before, before)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []rulepolicy.Version{}
	for rows.Next() {
		var p string
		var v rulepolicy.Version
		if e = rows.Scan(&p); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(p), &v); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) ChangeRulePolicy(ctx context.Context, c rulepolicy.Change, actor string) (rulepolicy.Version, error) {
	var out rulepolicy.Version
	if !rulepolicy.Text(actor, 64) || !rulepolicy.Text(c.Reason, 4096) || c.ExpectedRevision < 1 {
		return out, rulepolicy.ErrInvalid
	}
	if c.Action != "save" && c.Action != "rollback" {
		return out, rulepolicy.ErrInvalid
	}
	if _, ok := rulepolicy.Defaults()[c.Rule]; !ok {
		return out, rulepolicy.ErrInvalid
	}
	versions, active := policyTables(c.Rule)
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	policies, e := loadRulePolicies(ctx, tx)
	if e != nil {
		return out, e
	}
	prior := policies[c.Rule]
	if prior.Revision != c.ExpectedRevision {
		return out, rulepolicy.ErrConflict
	}
	cfg := c.Config
	if c.Action == "rollback" {
		if c.TargetRevision < 1 || c.TargetRevision >= prior.Revision {
			return out, rulepolicy.ErrInvalid
		}
		var p string
		e = tx.QueryRowContext(ctx, "SELECT payload FROM "+versions+" WHERE rule=? AND revision=?", c.Rule, c.TargetRevision).Scan(&p)
		if errors.Is(e, sql.ErrNoRows) {
			return out, rulepolicy.ErrNotFound
		}
		if e != nil {
			return out, e
		}
		var restored rulepolicy.Version
		if e = json.Unmarshal([]byte(p), &restored); e != nil {
			return out, e
		}
		cfg = restored.Config
	}
	cfg, e = rulepolicy.Canonical(c.Rule, cfg)
	if e != nil {
		return out, e
	}
	out = rulepolicy.Version{Rule: c.Rule, Revision: prior.Revision + 1, Config: cfg, Actor: actor, At: time.Now().UTC(), Reason: c.Reason}
	if c.Action == "rollback" {
		out.RestoredFrom = c.TargetRevision
	}
	p, _ := json.Marshal(out)
	retention, e := retentionPolicy(ctx, tx)
	if e != nil {
		return out, e
	}
	if e = s.checkWrite(ctx, tx, retention, int64(len(p))*16+(64<<10), true); e != nil {
		return out, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO "+versions+" VALUES(?,?,?)", out.Rule, out.Revision, string(p)); e != nil {
		return out, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE "+active+" SET revision=? WHERE rule=?", out.Revision, out.Rule); e != nil {
		return out, e
	}
	return out, tx.Commit()
}

func (s *Store) RulePolicyVersion(ctx context.Context, id string, revision int64) (rulepolicy.Version, error) {
	var v rulepolicy.Version
	if _, ok := rulepolicy.Defaults()[id]; !ok || revision < 1 {
		return v, rulepolicy.ErrInvalid
	}
	var p string
	versions, _ := policyTables(id)
	e := s.db.QueryRowContext(ctx, "SELECT payload FROM "+versions+" WHERE rule=? AND revision=?", id, revision).Scan(&p)
	if errors.Is(e, sql.ErrNoRows) {
		return v, rulepolicy.ErrNotFound
	}
	if e != nil {
		return v, e
	}
	e = json.Unmarshal([]byte(p), &v)
	return v, e
}

// New rule-family tables keep rollback to a pre-chain server compatible: older
// binaries validate the native policy count and must still see exactly 10 rows.
func policyTables(id string) (string, string) {
	if id == "chain.kerberos_logon" || id == "chain.explicit_credentials_logon" {
		return "correlation_windows_policy_versions", "correlation_windows_policy_active"
	}
	if strings.HasPrefix(id, "chain.") {
		return "correlation_chain_policy_versions", "correlation_chain_policy_active"
	}
	return "correlation_policy_versions", "correlation_policy_active"
}
