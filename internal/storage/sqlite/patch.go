// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/patch"
	"time"
)

func (s *Store) PatchCommand(ctx context.Context, c patch.Command, now time.Time) (patch.Job, error) {
	var j patch.Job
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return j, e
	}
	defer tx.Rollback()
	if e = checkAdmin(ctx, tx, true); e != nil {
		return j, e
	}
	actor := "cli"
	if u, ok := admin.Principal(ctx); ok {
		actor = u.Username
		if actor == "" {
			return j, admin.ErrForbidden
		}
	}
	if c.Action == "cancel" {
		res, e := tx.ExecContext(ctx, "UPDATE patch_jobs SET state='canceled' WHERE id=? AND state='queued'", c.ID)
		if e != nil {
			return j, e
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return j, patch.ErrConflict
		}
		if e = jobEvent(ctx, tx, "patch.canceled", c.ID, actor, nil); e != nil {
			return j, e
		}
		return j, tx.Commit()
	}
	if c.Action != "preview" && c.Action != "install" || len(c.UpdateIDs) < 1 || len(c.UpdateIDs) > 20 {
		return j, patch.ErrInvalid
	}
	var payload, inventoryID string
	e = tx.QueryRowContext(ctx, `SELECT i.id,i.payload FROM agents a JOIN agent_status st ON st.agent_id=a.id JOIN inventories i ON i.id=st.latest_inventory_id WHERE a.id=? AND a.revoked=0`, c.AgentID).Scan(&inventoryID, &payload)
	if errors.Is(e, sql.ErrNoRows) {
		return j, patch.ErrInvalid
	}
	if e != nil {
		return j, e
	}
	var snap inventory.Snapshot
	if json.Unmarshal([]byte(payload), &snap) != nil {
		return j, patch.ErrInvalid
	}
	if inventoryID != c.InventoryID || now.Sub(snap.CollectedAt) > 24*time.Hour || snap.CollectedAt.After(now.Add(time.Minute)) {
		return j, patch.ErrConflict
	}
	id, e := domain.NewID()
	if e != nil {
		return j, e
	}
	q := patch.Request{SchemaVersion: 1, ID: id, AgentID: c.AgentID, InventoryID: inventoryID, Mode: c.Action, Manager: snap.PackageManager, ExpiresAt: now.UTC().Add(time.Hour).Truncate(time.Second), NoReboot: true}
	if snap.OS.Family == "windows" {
		q.Manager = "wua"
	}
	if q.Manager != "wua" && q.Manager != "apt" && q.Manager != "dnf" {
		return j, patch.ErrInvalid
	}
	seen := map[string]bool{}
	for _, id := range c.UpdateIDs {
		if seen[id] {
			return j, patch.ErrInvalid
		}
		seen[id] = true
		found := false
		for _, u := range snap.Updates {
			if u.ID == id && u.State == "available" {
				q.Updates = append(q.Updates, u)
				found = true
				break
			}
		}
		if !found {
			return j, patch.ErrInvalid
		}
	}
	if c.Action == "install" {
		q.PreviewID = c.PreviewID
	}
	if e = q.Validate(); e != nil {
		return j, e
	}
	if c.Action == "install" {
		var raw, result, at string
		e = tx.QueryRowContext(ctx, "SELECT request,result,created_at FROM patch_jobs WHERE id=? AND agent_id=? AND state='succeeded'", c.PreviewID, c.AgentID).Scan(&raw, &result, &at)
		if e != nil {
			return j, patch.ErrConflict
		}
		var p patch.Request
		var r patch.Result
		json.Unmarshal([]byte(raw), &p)
		json.Unmarshal([]byte(result), &r)
		created, _ := parse(at)
		if p.Mode != "preview" || p.InventoryID != q.InventoryID || p.Manager != q.Manager || now.Sub(created) > 15*time.Minute || len(p.Updates) != len(q.Updates) {
			return j, patch.ErrConflict
		}
		for _, u := range q.Updates {
			ok := false
			for _, v := range p.Updates {
				ok = ok || patch.Matches(u, v)
			}
			if !ok {
				return j, patch.ErrConflict
			}
		}
	}
	var active int
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM patch_jobs WHERE agent_id=? AND state IN ('queued','running')", q.AgentID).Scan(&active); e != nil {
		return j, e
	}
	if active > 0 {
		return j, patch.ErrConflict
	}
	b, _ := json.Marshal(q)
	var preview any
	if c.Action == "install" {
		preview = c.PreviewID
		var n int
		if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM patch_jobs WHERE preview_id=?", preview).Scan(&n); e != nil {
			return j, e
		}
		if n > 0 {
			return j, patch.ErrConflict
		}
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO patch_jobs(id,agent_id,request,state,preview_id,created_by,created_at) VALUES(?,?,?,'queued',?,?,?)", id, q.AgentID, string(b), preview, actor, stamp(now))
	if e != nil {
		return j, e
	}
	if e = jobEvent(ctx, tx, "patch.queued", id, actor, q); e != nil {
		return j, e
	}
	j = patch.Job{Request: q, State: "queued", CreatedBy: actor, CreatedAt: now}
	return j, tx.Commit()
}
func (s *Store) PatchJobs(ctx context.Context, agent string) ([]patch.Job, error) {
	rows, e := s.db.QueryContext(ctx, "SELECT sequence,request,state,created_by,created_at,result FROM patch_jobs WHERE (?='' OR agent_id=?) ORDER BY sequence DESC LIMIT 100", agent, agent)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []patch.Job{}
	for rows.Next() {
		var j patch.Job
		var q, at string
		var r sql.NullString
		if e = rows.Scan(&j.Sequence, &q, &j.State, &j.CreatedBy, &at, &r); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(q), &j.Request); e != nil {
			return nil, e
		}
		j.CreatedAt, _ = parse(at)
		if r.Valid {
			if e = json.Unmarshal([]byte(r.String), &j.Result); e != nil {
				return nil, e
			}
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
func (s *Store) ClaimPatch(ctx context.Context, agent, hash string, now time.Time) (*patch.Request, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if _, e = agentBinding(ctx, tx, agent, hash); e != nil {
		return nil, e
	}
	var raw, state string
	e = tx.QueryRowContext(ctx, "SELECT request,state FROM patch_jobs WHERE agent_id=? AND state IN ('queued','running') ORDER BY sequence LIMIT 1", agent).Scan(&raw, &state)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var q patch.Request
	if e = json.Unmarshal([]byte(raw), &q); e != nil {
		return nil, e
	}
	if state == "queued" {
		if _, e = tx.ExecContext(ctx, "UPDATE patch_jobs SET state='running' WHERE id=?", q.ID); e != nil {
			return nil, e
		}
		if e = jobEvent(ctx, tx, "patch.started", q.ID, agent, nil); e != nil {
			return nil, e
		}
	}
	return &q, tx.Commit()
}
func (s *Store) FinishPatch(ctx context.Context, agent, hash string, r patch.Result, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = agentBinding(ctx, tx, agent, hash); e != nil {
		return e
	}
	var raw, state string
	var prior sql.NullString
	e = tx.QueryRowContext(ctx, "SELECT request,state,result FROM patch_jobs WHERE id=? AND agent_id=?", r.ID, agent).Scan(&raw, &state, &prior)
	if e != nil {
		return patch.ErrInvalid
	}
	var q patch.Request
	if json.Unmarshal([]byte(raw), &q) != nil || r.Validate(q) != nil {
		return patch.ErrInvalid
	}
	b, _ := json.Marshal(r)
	if prior.Valid {
		if prior.String == string(b) {
			return nil
		}
		return patch.ErrConflict
	}
	if state != "running" {
		return patch.ErrConflict
	}
	if _, e = tx.ExecContext(ctx, "UPDATE patch_jobs SET state=?,result=? WHERE id=?", r.Status, string(b), r.ID); e != nil {
		return e
	}
	if e = jobEvent(ctx, tx, "patch.finished", q.ID, agent, r); e != nil {
		return e
	}
	return tx.Commit()
}
