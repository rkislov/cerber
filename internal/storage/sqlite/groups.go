// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/jobs"
)

const groupSelect = `SELECT g.id,g.name,g.description,g.archived,g.version,g.created_by,g.created_at,
 (SELECT count(*) FROM agent_group_members m WHERE m.group_id=g.id),
 (SELECT count(*) FROM agent_group_members m JOIN agents a ON a.id=m.agent_id WHERE m.group_id=g.id AND a.revoked=0)
 FROM agent_groups g `

func scanGroup(row interface{ Scan(...any) error }) (jobs.Group, error) {
	var g jobs.Group
	var at string
	err := row.Scan(&g.ID, &g.Name, &g.Description, &g.Archived, &g.Version, &g.CreatedBy, &at, &g.Members, &g.Active)
	if err != nil {
		return g, err
	}
	g.CreatedAt, err = parse(at)
	g.Revoked = g.Members - g.Active
	return g, err
}
func groupInfo(ctx context.Context, q rowQuerier, id string) (jobs.Group, error) {
	g, err := scanGroup(q.QueryRowContext(ctx, groupSelect+"WHERE g.id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		err = domain.ErrNotFound
	}
	return g, err
}
func (s *Store) AgentGroup(ctx context.Context, id string) (jobs.Group, error) {
	return groupInfo(ctx, s.db, id)
}
func (s *Store) AgentGroups(ctx context.Context, state, after string, limit int) ([]jobs.Group, error) {
	if limit < 1 || limit > 101 || state != "active" && state != "archived" && state != "all" {
		return nil, jobs.ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, groupSelect+"WHERE (?='all' OR g.archived=?) AND g.id>? ORDER BY g.id LIMIT ?", state, state == "archived", after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []jobs.Group{}
	for rows.Next() {
		g, e := scanGroup(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
func (s *Store) AgentGroupMembers(ctx context.Context, id, after string, limit int) ([]jobs.GroupMember, error) {
	if limit < 1 || limit > 101 {
		return nil, jobs.ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, `SELECT a.id,s.name,s.ip,a.revoked,1 FROM agent_group_members m JOIN agents a ON a.id=m.agent_id JOIN assets s ON s.id=a.asset_id WHERE m.group_id=? AND m.agent_id>? ORDER BY m.agent_id LIMIT ?`, id, after, limit)
	if err != nil {
		return nil, err
	}
	return scanGroupMembers(rows)
}
func (s *Store) AgentGroupCandidates(ctx context.Context, id, search, after string, limit int) ([]jobs.GroupMember, error) {
	if limit < 1 || limit > 51 || len(search) > 128 {
		return nil, jobs.ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, `SELECT a.id,s.name,s.ip,a.revoked,EXISTS(SELECT 1 FROM agent_group_members m WHERE m.group_id=? AND m.agent_id=a.id) FROM agents a JOIN assets s ON s.id=a.asset_id WHERE a.revoked=0 AND a.id>? AND (?='' OR instr(lower(s.name||' '||s.ip||' '||a.id),lower(?))>0) ORDER BY a.id LIMIT ?`, id, after, search, search, limit)
	if err != nil {
		return nil, err
	}
	return scanGroupMembers(rows)
}
func scanGroupMembers(rows *sql.Rows) ([]jobs.GroupMember, error) {
	defer rows.Close()
	out := []jobs.GroupMember{}
	for rows.Next() {
		var m jobs.GroupMember
		if err := rows.Scan(&m.AgentID, &m.AssetName, &m.AssetIP, &m.Revoked, &m.Member); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
func groupText(v string, max int) bool {
	if !utf8.ValidString(v) || len(v) > max {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func (s *Store) GroupCommand(ctx context.Context, c jobs.GroupCommand, now time.Time) (string, error) {
	c.Name = strings.TrimSpace(c.Name)
	switch c.Action {
	case "create", "update":
		if c.Name == "" || !groupText(c.Name, 128) || !groupText(c.Description, 1024) {
			return "", jobs.ErrInvalid
		}
	case "archive", "restore", "run", "run.cancel", "members.add", "members.remove", "schedule.create", "schedule.update", "schedule.enable", "schedule.disable":
	default:
		return "", jobs.ErrInvalid
	}
	if c.Action == "run" || c.Action == "schedule.create" || c.Action == "schedule.update" {
		if !jobs.ValidKind(c.Kind) || c.RefreshMetadata && c.Kind != "updates" {
			return "", jobs.ErrInvalid
		}
	}
	if c.Action == "schedule.create" || c.Action == "schedule.update" {
		if c.IntervalSeconds < 60 || c.IntervalSeconds > 2592000 || c.FirstRunAt.IsZero() || c.FirstRunAt.Before(now.Add(-time.Minute)) || c.FirstRunAt.After(now.Add(365*24*time.Hour)) {
			return "", jobs.ErrInvalid
		}
	}
	if c.Action == "members.add" || c.Action == "members.remove" {
		if len(c.AgentIDs) < 1 || len(c.AgentIDs) > 100 {
			return "", jobs.ErrInvalid
		}
		unique := map[string]bool{}
		ids := []string{}
		for _, id := range c.AgentIDs {
			if !ingest.Identifier(id) {
				return "", jobs.ErrInvalid
			}
			if !unique[id] {
				unique[id] = true
				ids = append(ids, id)
			}
		}
		c.AgentIDs = ids
	}
	if c.Action != "create" && c.Action != "run.cancel" && !strings.HasPrefix(c.Action, "schedule.") {
		if !ingest.Identifier(c.GroupID) {
			return "", jobs.ErrInvalid
		}
	}
	if c.Action == "run.cancel" || strings.HasPrefix(c.Action, "schedule.") && c.Action != "schedule.create" {
		if !ingest.Identifier(c.ID) {
			return "", jobs.ErrInvalid
		}
	}
	if c.Action == "schedule.create" && !ingest.Identifier(c.GroupID) {
		return "", jobs.ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if err = checkAdmin(ctx, tx, false); err != nil {
		return "", err
	}
	actor := "cli"
	if u, ok := admin.Principal(ctx); ok {
		actor = u.Username
		if actor == "" {
			actor = "legacy-administrator"
		}
	}
	if c.Action == "run.cancel" {
		var exists int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM agent_group_runs WHERE id=?", c.ID).Scan(&exists); err != nil {
			return "", err
		}
		if exists == 0 {
			return "", domain.ErrNotFound
		}
		rows, e := tx.QueryContext(ctx, `SELECT j.id FROM agent_jobs j JOIN agent_group_run_members m ON m.job_id=j.id WHERE m.run_id=? AND j.state='queued' ORDER BY j.id`, c.ID)
		if e != nil {
			return "", e
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return "", e
			}
			ids = append(ids, id)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return "", e
		}
		res, e := tx.ExecContext(ctx, `UPDATE agent_jobs SET state='canceled',finished_at=? WHERE state='queued' AND id IN (SELECT job_id FROM agent_group_run_members WHERE run_id=?)`, stamp(now), c.ID)
		if e != nil {
			return "", e
		}
		n, _ := res.RowsAffected()
		for _, id := range ids {
			if err = jobEvent(ctx, tx, "agent.job.canceled", id, actor, map[string]string{"group_run_id": c.ID}); err != nil {
				return "", err
			}
		}
		if err = jobEvent(ctx, tx, "agent.group.run.canceled", c.ID, actor, map[string]int64{"queued_canceled": n}); err != nil {
			return "", err
		}
		return c.ID, tx.Commit()
	}
	if strings.HasPrefix(c.Action, "schedule.") && c.Action != "schedule.create" {
		if err = tx.QueryRowContext(ctx, "SELECT group_id FROM agent_group_schedules WHERE id=?", c.ID).Scan(&c.GroupID); errors.Is(err, sql.ErrNoRows) {
			return "", domain.ErrNotFound
		} else if err != nil {
			return "", err
		}
	}
	var g jobs.Group
	if c.Action != "create" {
		g, err = groupInfo(ctx, tx, c.GroupID)
		if err != nil {
			return "", err
		}
		if c.GroupVersion != g.Version {
			return "", domain.ErrConflict
		}
		if g.Archived && c.Action != "restore" && c.Action != "update" && c.Action != "schedule.disable" {
			return "", domain.ErrConflict
		}
	}
	id := c.GroupID
	switch c.Action {
	case "create", "update":
		var n int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM agent_groups WHERE name=? AND id<>?", c.Name, c.GroupID).Scan(&n); err != nil {
			return "", err
		}
		if n != 0 {
			return "", domain.ErrConflict
		}
		if c.Action == "create" {
			id, err = domain.NewID()
			if err != nil {
				return "", err
			}
			_, err = tx.ExecContext(ctx, "INSERT INTO agent_groups(id,name,description,created_by,created_at) VALUES(?,?,?,?,?)", id, c.Name, c.Description, actor, stamp(now))
		} else {
			_, err = tx.ExecContext(ctx, "UPDATE agent_groups SET name=?,description=?,version=version+1 WHERE id=?", c.Name, c.Description, id)
		}
	case "archive", "restore":
		_, err = tx.ExecContext(ctx, "UPDATE agent_groups SET archived=?,version=version+1 WHERE id=?", c.Action == "archive", id)
		if err == nil && c.Action == "archive" {
			_, err = tx.ExecContext(ctx, "UPDATE agent_group_schedules SET enabled=0 WHERE group_id=?", id)
		}
	case "members.add", "members.remove":
		for _, agent := range c.AgentIDs {
			if c.Action == "members.add" {
				var revoked bool
				if err = tx.QueryRowContext(ctx, "SELECT revoked FROM agents WHERE id=?", agent).Scan(&revoked); errors.Is(err, sql.ErrNoRows) {
					return "", domain.ErrNotFound
				} else if err != nil {
					return "", err
				}
				if revoked {
					return "", domain.ErrConflict
				}
				_, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO agent_group_members(group_id,agent_id,added_at) VALUES(?,?,?)", id, agent, stamp(now))
			} else {
				_, err = tx.ExecContext(ctx, "DELETE FROM agent_group_members WHERE group_id=? AND agent_id=?", id, agent)
			}
			if err != nil {
				return "", err
			}
		}
		var n int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM agent_group_members WHERE group_id=?", id).Scan(&n); err != nil {
			return "", err
		}
		if n > jobs.MaxGroupMembers {
			return "", domain.ErrConflict
		}
		_, err = tx.ExecContext(ctx, "UPDATE agent_groups SET version=version+1 WHERE id=?", id)
	case "run":
		id, err = insertGroupRun(ctx, tx, g, c.Kind, c.RefreshMetadata, "", actor, now)
		if err != nil {
			return "", err
		}
		return id, tx.Commit()
	case "schedule.create":
		var n int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM agent_group_schedules WHERE group_id=?", id).Scan(&n); err != nil {
			return "", err
		}
		if n >= 20 {
			return "", domain.ErrConflict
		}
		id, err = domain.NewID()
		if err != nil {
			return "", err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO agent_group_schedules(id,group_id,kind,refresh_metadata,interval_seconds,next_run_at,created_by) VALUES(?,?,?,?,?,?,?)", id, c.GroupID, c.Kind, c.RefreshMetadata, c.IntervalSeconds, stamp(c.FirstRunAt), actor)
	case "schedule.update":
		id = c.ID
		_, err = tx.ExecContext(ctx, "UPDATE agent_group_schedules SET kind=?,refresh_metadata=?,interval_seconds=?,next_run_at=? WHERE id=?", c.Kind, c.RefreshMetadata, c.IntervalSeconds, stamp(c.FirstRunAt), id)
	case "schedule.enable", "schedule.disable":
		id = c.ID
		_, err = tx.ExecContext(ctx, "UPDATE agent_group_schedules SET enabled=?,next_run_at=CASE WHEN ? THEN ? ELSE next_run_at END WHERE id=?", c.Action == "schedule.enable", c.Action == "schedule.enable", stamp(now), id)
	}
	if err != nil {
		return "", err
	}
	if err = jobEvent(ctx, tx, "agent.group."+c.Action, id, actor, c); err != nil {
		return "", err
	}
	return id, tx.Commit()
}
func insertGroupRun(ctx context.Context, tx *sql.Tx, g jobs.Group, kind string, refresh bool, schedule, actor string, now time.Time) (string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT a.id,s.name,s.ip,a.revoked FROM agent_group_members m JOIN agents a ON a.id=m.agent_id JOIN assets s ON s.id=a.asset_id WHERE m.group_id=? ORDER BY m.agent_id LIMIT ?`, g.ID, jobs.MaxGroupMembers+1)
	if err != nil {
		return "", err
	}
	members := []jobs.GroupMember{}
	for rows.Next() {
		var m jobs.GroupMember
		if err = rows.Scan(&m.AgentID, &m.AssetName, &m.AssetIP, &m.Revoked); err != nil {
			rows.Close()
			return "", err
		}
		members = append(members, m)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	if len(members) > jobs.MaxGroupMembers || len(members) == 0 && schedule == "" {
		return "", domain.ErrConflict
	}
	id, err := domain.NewID()
	if err != nil {
		return "", err
	}
	var scheduleID any
	if schedule != "" {
		scheduleID = schedule
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO agent_group_runs(id,group_id,group_name,schedule_id,kind,refresh_metadata,created_at,created_by) VALUES(?,?,?,?,?,?,?,?)", id, g.ID, g.Name, scheduleID, kind, refresh, stamp(now), actor)
	if err != nil {
		return "", err
	}
	queued, skipped := 0, 0
	for _, m := range members {
		reason := ""
		jobID := ""
		if m.Revoked {
			reason = "agent_revoked"
		}
		if reason == "" && schedule != "" {
			var n int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM agent_group_run_members m JOIN agent_group_runs r ON r.id=m.run_id JOIN agent_jobs j ON j.id=m.job_id WHERE r.schedule_id=? AND m.agent_id=? AND j.state IN ('queued','running')`, schedule, m.AgentID).Scan(&n); err != nil {
				return "", err
			}
			if n > 0 {
				reason = "previous_run_pending"
			}
		}
		if reason == "" {
			jobID, err = insertJob(ctx, tx, jobs.Command{AgentID: m.AgentID, Kind: kind, RefreshMetadata: refresh, GroupRunID: id, Scheduled: schedule != ""}, "", actor, now)
			if errors.Is(err, domain.ErrConflict) {
				reason = "queue_full"
				err = nil
			} else if err != nil {
				return "", err
			}
		}
		var job any
		if reason == "" {
			job = jobID
			queued++
		} else {
			skipped++
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO agent_group_run_members(run_id,agent_id,asset_name,asset_ip,job_id,skip_reason) VALUES(?,?,?,?,?,?)", id, m.AgentID, m.AssetName, m.AssetIP, job, reason); err != nil {
			return "", err
		}
	}
	eventActor := actor
	if schedule != "" {
		eventActor = "scheduler"
	}
	if err = jobEvent(ctx, tx, "agent.group.run.created", id, eventActor, map[string]any{"group_id": g.ID, "group_name": g.Name, "schedule_id": schedule, "created_by": actor, "total": len(members), "queued": queued, "skipped": skipped}); err != nil {
		return "", err
	}
	return id, nil
}
func advanceGroupSchedules(ctx context.Context, tx *sql.Tx, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT s.id,s.group_id,g.name,g.archived,s.kind,s.refresh_metadata,s.interval_seconds,s.next_run_at,s.created_by FROM agent_group_schedules s JOIN agent_groups g ON g.id=s.group_id WHERE s.enabled=1 AND (s.next_run_at<=? OR g.archived=1) ORDER BY s.next_run_at,s.id LIMIT 5`, stamp(now))
	if err != nil {
		return err
	}
	type due struct {
		s        jobs.GroupSchedule
		archived bool
	}
	items := []due{}
	for rows.Next() {
		var v due
		var at string
		if err = rows.Scan(&v.s.ID, &v.s.GroupID, &v.s.GroupName, &v.archived, &v.s.Kind, &v.s.RefreshMetadata, &v.s.IntervalSeconds, &at, &v.s.CreatedBy); err != nil {
			rows.Close()
			return err
		}
		v.s.NextRunAt, err = parse(at)
		if err != nil {
			rows.Close()
			return err
		}
		items = append(items, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, v := range items {
		if v.archived {
			if _, err = tx.ExecContext(ctx, "UPDATE agent_group_schedules SET enabled=0 WHERE id=?", v.s.ID); err != nil {
				return err
			}
			continue
		}
		if _, err = insertGroupRun(ctx, tx, jobs.Group{ID: v.s.GroupID, Name: v.s.GroupName}, v.s.Kind, v.s.RefreshMetadata, v.s.ID, v.s.CreatedBy, now); err != nil {
			return err
		}
		interval := time.Duration(v.s.IntervalSeconds) * time.Second
		next := v.s.NextRunAt.Add((now.Sub(v.s.NextRunAt)/interval + 1) * interval)
		if _, err = tx.ExecContext(ctx, "UPDATE agent_group_schedules SET next_run_at=? WHERE id=?", stamp(next), v.s.ID); err != nil {
			return err
		}
	}
	return nil
}
