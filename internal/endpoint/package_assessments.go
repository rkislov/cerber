// SPDX-License-Identifier: Apache-2.0
package endpoint

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"github.com/rkislov/cerber/internal/netscan"
	"github.com/rkislov/cerber/internal/vuln"
	"time"
)

type AssessmentEntry struct {
	Sequence   int64                  `json:"sequence"`
	Finding    string                 `json:"finding"`
	CPE        string                 `json:"cpe"`
	Assessment vuln.PackageAssessment `json:"assessment"`
}

func (s *Server) networkBinding(ctx context.Context, ip string) vuln.InventoryBinding {
	if s.Inventory == nil {
		return vuln.InventoryBinding{Link: vuln.InventoryLink{State: "unknown", Reason: "Источник аутентифицированного инвентаря не подключён"}}
	}
	b, e := s.Inventory.VulnerabilityInventory(ctx, ip)
	if e != nil {
		return vuln.InventoryBinding{Link: vuln.InventoryLink{State: "unknown", Reason: "Не удалось прочитать инвентарь агента"}}
	}
	return b
}
func (s *Server) assessHost(ctx context.Context, h *netscan.Host) {
	binding := s.networkBinding(ctx, h.IP)
	h.Inventory = &binding.Link
	for i := range h.Vulnerabilities {
		a := s.Catalog.AssessPackage(ctx, h.Vulnerabilities[i], binding, time.Now().UTC())
		h.Vulnerabilities[i].Verification = &a
	}
}
func (s *Server) assessmentTargets(ctx context.Context, key string) []vuln.Match {
	rows, e := s.db.QueryContext(ctx, "SELECT payload FROM package_assessment_targets WHERE asset_key=?", key)
	if e != nil {
		return nil
	}
	defer rows.Close()
	out := []vuln.Match{}
	for rows.Next() {
		var p string
		var m vuln.Match
		if rows.Scan(&p) == nil && json.Unmarshal([]byte(p), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}
func (s *Server) saveAssessment(ctx context.Context, key string, m vuln.Match, a vuln.PackageAssessment) error {
	comparable := a
	comparable.CheckedAt = time.Time{}
	comparable.CollectedAt = time.Time{}
	comparable.SnapshotID = ""
	comparable.SourceFetched = time.Time{}
	data, e := json.Marshal(comparable)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(data)
	fingerprint := hex.EncodeToString(sum[:])
	payload, _ := json.Marshal(AssessmentEntry{Finding: m.ID, CPE: m.CPE, Assessment: a})
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var last string
	e = tx.QueryRowContext(ctx, "SELECT fingerprint FROM package_assessment_history WHERE asset_key=? AND finding=? ORDER BY sequence DESC LIMIT 1", key, m.ID).Scan(&last)
	if e != nil && e != sql.ErrNoRows {
		return e
	}
	if last != fingerprint {
		if _, e = tx.ExecContext(ctx, "INSERT INTO package_assessment_history(asset_key,finding,fingerprint,payload) VALUES(?,?,?,?)", key, m.ID, fingerprint, string(payload)); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Server) syncPackageAssessments(ctx context.Context, v NetworkView) error {
	ids := []string{}
	targets := map[string][]vuln.Match{}
	hosts := map[string]netscan.Asset{}
	for _, a := range v.Assets {
		key := a.Plan + ":" + a.Host.IP
		hosts[key] = a
		matches := s.networkVulns(ctx, a.Host)
		seen := map[string]bool{}
		for _, m := range matches {
			seen[m.ID] = true
			m.Attack = nil
			m.Verification = nil
			p, _ := json.Marshal(m)
			if _, e := s.db.ExecContext(ctx, "INSERT INTO package_assessment_targets VALUES(?,?,?) ON CONFLICT(asset_key,finding) DO UPDATE SET payload=excluded.payload", key, m.ID, string(p)); e != nil {
				return e
			}
		}
		for _, old := range s.assessmentTargets(ctx, key) {
			if !seen[old.ID] {
				matches = append(matches, old)
			}
		}
		targets[key] = matches
		for _, m := range matches {
			ids = append(ids, m.ID)
			ids = append(ids, m.CVEs...)
		}
	}
	s.Catalog.SyncUbuntu(ctx, ids)
	bindings := []vuln.InventoryBinding{}
	for _, h := range hosts {
		bindings = append(bindings, s.networkBinding(ctx, h.Host.IP))
	}
	s.Catalog.SyncOVAL(ctx, bindings)
	for key, matches := range targets {
		binding := s.networkBinding(ctx, hosts[key].Host.IP)
		for _, m := range matches {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			a := s.Catalog.AssessPackage(ctx, m, binding, time.Now().UTC())
			if e := s.saveAssessment(ctx, key, m, a); e != nil {
				return e
			}
		}
	}
	return nil
}
func (s *Server) AssessmentHistory(ctx context.Context, key, finding string) ([]AssessmentEntry, error) {
	out := []AssessmentEntry{}
	if len(key) > 160 || len(finding) > 64 {
		return out, ErrInvalid
	}
	rows, e := s.db.QueryContext(ctx, "SELECT sequence,payload FROM package_assessment_history WHERE asset_key=? AND (?='' OR finding=?) ORDER BY sequence DESC LIMIT 50", key, finding, finding)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var n int64
		var p string
		var a AssessmentEntry
		if e = rows.Scan(&n, &p); e != nil {
			return out, e
		}
		if e = json.Unmarshal([]byte(p), &a); e != nil {
			return out, e
		}
		a.Sequence = n
		out = append(out, a)
	}
	return out, rows.Err()
}
