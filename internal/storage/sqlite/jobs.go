// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/event"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/jobs"
	"time"
)

func jobEvent(ctx context.Context, tx *sql.Tx, kind, id, actor string, payload any) error {
	e, err := event.New(kind, id, map[string]any{"actor": actor, "details": payload})
	if err != nil {
		return err
	}
	return appendEvent(ctx, tx, e)
}
func insertJob(ctx context.Context, tx *sql.Tx, c jobs.Command, schedule, actor string, now time.Time) (string, error) {
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM agent_jobs WHERE agent_id=? AND state IN ('queued','running')", c.AgentID).Scan(&n); err != nil {
		return "", err
	}
	if n >= 20 {
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
	_, err = tx.ExecContext(ctx, `INSERT INTO agent_jobs(id,agent_id,schedule_id,kind,refresh_metadata,state,created_at,expires_at,created_by) VALUES(?,?,?,?,?,'queued',?,?,?)`, id, c.AgentID, scheduleID, c.Kind, c.RefreshMetadata, stamp(now), stamp(now.Add(jobs.QueueTTL)), actor)
	if err != nil {
		return "", err
	}
	eventActor := actor
	if schedule != "" {
		eventActor = "scheduler"
	}
	return id, jobEvent(ctx, tx, "agent.job.queued", id, eventActor, map[string]any{"agent_id": c.AgentID, "kind": c.Kind, "schedule_id": schedule, "created_by": actor, "refresh_metadata": c.RefreshMetadata})
}
func (s *Store) JobCommand(ctx context.Context, c jobs.Command, now time.Time) (string, error) {
	switch c.Action {
	case "run", "schedule.create":
		if !ingest.Identifier(c.AgentID) || !jobs.ValidKind(c.Kind) || c.RefreshMetadata && c.Kind != "updates" {
			return "", jobs.ErrInvalid
		}
	case "schedule.update":
		if !ingest.Identifier(c.ID) || !jobs.ValidKind(c.Kind) || c.RefreshMetadata && c.Kind != "updates" {
			return "", jobs.ErrInvalid
		}
	case "cancel", "schedule.enable", "schedule.disable":
		if !ingest.Identifier(c.ID) {
			return "", jobs.ErrInvalid
		}
	default:
		return "", jobs.ErrInvalid
	}
	if (c.Action == "schedule.create" || c.Action == "schedule.update") && (c.IntervalSeconds < 60 || c.IntervalSeconds > 2592000 || c.FirstRunAt.IsZero() || c.FirstRunAt.Before(now.Add(-time.Minute)) || c.FirstRunAt.After(now.Add(365*24*time.Hour))) {
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
	if c.Action == "run" || c.Action == "schedule.create" {
		var revoked bool
		err = tx.QueryRowContext(ctx, "SELECT revoked FROM agents WHERE id=?", c.AgentID).Scan(&revoked)
		if errors.Is(err, sql.ErrNoRows) {
			return "", domain.ErrNotFound
		}
		if err != nil {
			return "", err
		}
		if revoked {
			return "", domain.ErrConflict
		}
	}
	id := c.ID
	switch c.Action {
	case "run":
		id, err = insertJob(ctx, tx, c, "", actor, now)
	case "cancel":
		var res sql.Result
		res, err = tx.ExecContext(ctx, "UPDATE agent_jobs SET state='canceled',finished_at=? WHERE id=? AND state='queued'", stamp(now), id)
		if err == nil {
			n, _ := res.RowsAffected()
			if n == 0 {
				return "", domain.ErrConflict
			}
			err = jobEvent(ctx, tx, "agent.job.canceled", id, actor, nil)
		}
	case "schedule.create":
		var n int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM agent_schedules WHERE agent_id=?", c.AgentID).Scan(&n); err != nil {
			return "", err
		}
		if n >= 20 {
			return "", domain.ErrConflict
		}
		id, err = domain.NewID()
		if err != nil {
			return "", err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO agent_schedules(id,agent_id,kind,refresh_metadata,interval_seconds,next_run_at,created_by) VALUES(?,?,?,?,?,?,?)", id, c.AgentID, c.Kind, c.RefreshMetadata, c.IntervalSeconds, stamp(c.FirstRunAt), actor)
		if err == nil {
			err = jobEvent(ctx, tx, "agent.schedule.created", id, actor, c)
		}
	case "schedule.update":
		if err = tx.QueryRowContext(ctx, "SELECT agent_id FROM agent_schedules WHERE id=?", id).Scan(&c.AgentID); errors.Is(err, sql.ErrNoRows) {
			return "", domain.ErrNotFound
		} else if err != nil {
			return "", err
		}
		var res sql.Result
		res, err = tx.ExecContext(ctx, `UPDATE agent_schedules SET kind=?,refresh_metadata=?,interval_seconds=?,next_run_at=? WHERE id=? AND EXISTS(SELECT 1 FROM agents WHERE agents.id=agent_schedules.agent_id AND revoked=0)`, c.Kind, c.RefreshMetadata, c.IntervalSeconds, stamp(c.FirstRunAt), id)
		if err == nil {
			n, _ := res.RowsAffected()
			if n == 0 {
				return "", domain.ErrConflict
			}
			err = jobEvent(ctx, tx, "agent.schedule.updated", id, actor, c)
		}
	case "schedule.enable", "schedule.disable":
		var res sql.Result
		res, err = tx.ExecContext(ctx, `UPDATE agent_schedules SET enabled=?,next_run_at=CASE WHEN ? THEN ? ELSE next_run_at END WHERE id=? AND EXISTS(SELECT 1 FROM agents WHERE agents.id=agent_schedules.agent_id AND revoked=0)`, c.Action == "schedule.enable", c.Action == "schedule.enable", stamp(now), id)
		if err == nil {
			n, _ := res.RowsAffected()
			if n == 0 {
				return "", domain.ErrConflict
			}
			kind := "agent.schedule.disabled"
			if c.Action == "schedule.enable" {
				kind = "agent.schedule.enabled"
			}
			err = jobEvent(ctx, tx, kind, id, actor, nil)
		}
	}
	if err != nil {
		return "", err
	}
	return id, tx.Commit()
}

const jobSelect = `SELECT j.sequence,j.id,j.agent_id,a.name,a.ip,COALESCE(j.schedule_id,''),j.kind,j.refresh_metadata,j.state,j.created_at,j.started_at,j.finished_at,j.expires_at,j.created_by,j.result,j.inventory_id FROM agent_jobs j JOIN agents g ON g.id=j.agent_id JOIN assets a ON a.id=g.asset_id `

func scanJob(row interface{ Scan(...any) error }) (jobs.Job, error) {
	var j jobs.Job
	var created, expires string
	var started, finished, result sql.NullString
	err := row.Scan(&j.Sequence, &j.ID, &j.AgentID, &j.AssetName, &j.AssetIP, &j.ScheduleID, &j.Kind, &j.RefreshMetadata, &j.State, &created, &started, &finished, &expires, &j.CreatedBy, &result, &j.InventoryID)
	if err != nil {
		return j, err
	}
	j.CreatedAt, err = parse(created)
	if err != nil {
		return j, err
	}
	j.ExpiresAt, err = parse(expires)
	if err != nil {
		return j, err
	}
	if started.Valid {
		v, e := parse(started.String)
		if e != nil {
			return j, e
		}
		j.StartedAt = &v
	}
	if finished.Valid {
		v, e := parse(finished.String)
		if e != nil {
			return j, e
		}
		j.FinishedAt = &v
	}
	if result.Valid {
		j.Result = &jobs.Result{}
		err = json.Unmarshal([]byte(result.String), j.Result)
	}
	return j, err
}
func (s *Store) Jobs(ctx context.Context, agent string, before int64, limit int) ([]jobs.Job, error) {
	if before < 0 || limit < 1 || limit > 101 {
		return nil, jobs.ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, jobSelect+`WHERE (?='' OR j.agent_id=?) AND (?=0 OR j.sequence<?) ORDER BY j.sequence DESC LIMIT ?`, agent, agent, before, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []jobs.Job{}
	for rows.Next() {
		j, e := scanJob(rows)
		if e != nil {
			return nil, e
		}
		result = append(result, j)
	}
	return result, rows.Err()
}
func (s *Store) JobSchedules(ctx context.Context, agent, after string, limit int) ([]jobs.Schedule, error) {
	if limit < 1 || limit > 101 {
		return nil, jobs.ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, `SELECT s.id,s.agent_id,a.name,a.ip,s.kind,s.refresh_metadata,s.interval_seconds,s.next_run_at,s.enabled,s.created_by FROM agent_schedules s JOIN agents g ON g.id=s.agent_id JOIN assets a ON a.id=g.asset_id WHERE (?='' OR s.agent_id=?) AND s.id>? ORDER BY s.id LIMIT ?`, agent, agent, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []jobs.Schedule{}
	for rows.Next() {
		var v jobs.Schedule
		var at string
		if err = rows.Scan(&v.ID, &v.AgentID, &v.AssetName, &v.AssetIP, &v.Kind, &v.RefreshMetadata, &v.IntervalSeconds, &at, &v.Enabled, &v.CreatedBy); err != nil {
			return nil, err
		}
		v.NextRunAt, err = parse(at)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// AdvanceJobs processes bounded batches and skips missed intervals instead of
// replaying an unbounded backlog after server downtime.
func (s *Store) AdvanceJobs(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT j.id,j.state,g.revoked FROM agent_jobs j JOIN agents g ON g.id=j.agent_id WHERE j.state IN ('queued','running') AND (j.expires_at<=? OR g.revoked=1) ORDER BY j.sequence LIMIT 100`, stamp(now))
	if err != nil {
		return err
	}
	type expired struct {
		id, state string
		revoked   bool
	}
	ending := []expired{}
	for rows.Next() {
		var v expired
		if err = rows.Scan(&v.id, &v.state, &v.revoked); err != nil {
			rows.Close()
			return err
		}
		ending = append(ending, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, v := range ending {
		state := "expired"
		if v.state == "running" {
			state = "timed_out"
		}
		if v.revoked {
			state = "canceled"
		}
		if _, err = tx.ExecContext(ctx, "UPDATE agent_jobs SET state=?,finished_at=? WHERE id=?", state, stamp(now), v.id); err != nil {
			return err
		}
		reason := "queue_expired"
		if v.state == "running" {
			reason = "execution_lease_expired"
		}
		if v.revoked {
			reason = "agent_revoked"
		}
		if err = jobEvent(ctx, tx, "agent.job."+state, v.id, "scheduler", map[string]string{"reason": reason}); err != nil {
			return err
		}
	}
	rows, err = tx.QueryContext(ctx, `SELECT s.id,s.agent_id,s.kind,s.refresh_metadata,s.interval_seconds,s.next_run_at,s.created_by,g.revoked FROM agent_schedules s JOIN agents g ON g.id=s.agent_id WHERE s.enabled=1 AND (s.next_run_at<=? OR g.revoked=1) ORDER BY s.next_run_at,s.id LIMIT 100`, stamp(now))
	if err != nil {
		return err
	}
	type due struct {
		s       jobs.Schedule
		revoked bool
	}
	dueItems := []due{}
	for rows.Next() {
		var v due
		var at string
		if err = rows.Scan(&v.s.ID, &v.s.AgentID, &v.s.Kind, &v.s.RefreshMetadata, &v.s.IntervalSeconds, &at, &v.s.CreatedBy, &v.revoked); err != nil {
			rows.Close()
			return err
		}
		v.s.NextRunAt, err = parse(at)
		if err != nil {
			rows.Close()
			return err
		}
		dueItems = append(dueItems, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, v := range dueItems {
		if v.revoked {
			if _, err = tx.ExecContext(ctx, "UPDATE agent_schedules SET enabled=0 WHERE id=?", v.s.ID); err != nil {
				return err
			}
			if err = jobEvent(ctx, tx, "agent.schedule.disabled", v.s.ID, "scheduler", map[string]string{"reason": "agent_revoked"}); err != nil {
				return err
			}
			continue
		}
		var pending int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM agent_jobs WHERE schedule_id=? AND state IN ('queued','running')", v.s.ID).Scan(&pending); err != nil {
			return err
		}
		if pending == 0 {
			_, err = insertJob(ctx, tx, jobs.Command{AgentID: v.s.AgentID, Kind: v.s.Kind, RefreshMetadata: v.s.RefreshMetadata}, v.s.ID, v.s.CreatedBy, now)
			if err != nil && !errors.Is(err, domain.ErrConflict) {
				return err
			}
			if errors.Is(err, domain.ErrConflict) {
				if err = jobEvent(ctx, tx, "agent.schedule.skipped", v.s.ID, "scheduler", map[string]string{"reason": "queue_full"}); err != nil {
					return err
				}
			}
		} else {
			if err = jobEvent(ctx, tx, "agent.schedule.skipped", v.s.ID, "scheduler", map[string]string{"reason": "previous_run_pending"}); err != nil {
				return err
			}
		}

		interval := time.Duration(v.s.IntervalSeconds) * time.Second
		next := v.s.NextRunAt.Add((now.Sub(v.s.NextRunAt)/interval + 1) * interval)
		if _, err = tx.ExecContext(ctx, "UPDATE agent_schedules SET next_run_at=? WHERE id=?", stamp(next), v.s.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) ClaimJob(ctx context.Context, agent, hash string, now time.Time) (*jobs.Job, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = agentBinding(ctx, tx, agent, hash); err != nil {
		return nil, err
	}
	j, err := scanJob(tx.QueryRowContext(ctx, jobSelect+`WHERE j.agent_id=? AND j.state='queued' AND j.expires_at>? AND NOT EXISTS(SELECT 1 FROM agent_jobs WHERE agent_id=? AND state='running') ORDER BY j.sequence LIMIT 1`, agent, stamp(now), agent))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	j.State = "running"
	j.StartedAt = &now
	j.ExpiresAt = now.Add(jobs.Lease)
	if _, err = tx.ExecContext(ctx, "UPDATE agent_jobs SET state='running',started_at=?,expires_at=? WHERE id=?", stamp(now), stamp(j.ExpiresAt), j.ID); err != nil {
		return nil, err
	}
	if err = jobEvent(ctx, tx, "agent.job.started", j.ID, agent, nil); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &j, nil
}
func (s *Store) FinishJob(ctx context.Context, agent, hash string, result jobs.Result, now time.Time) error {
	if !ingest.Identifier(result.JobID) || result.ReportID != "" && !ingest.Identifier(result.ReportID) || result.Validate() != nil {
		return jobs.ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = agentBinding(ctx, tx, agent, hash); err != nil {
		return err
	}
	j, err := scanJob(tx.QueryRowContext(ctx, jobSelect+"WHERE j.id=? AND j.agent_id=?", result.JobID, agent))
	if errors.Is(err, sql.ErrNoRows) {
		return jobs.ErrTerminal
	}
	if err != nil {
		return err
	}
	if j.Result != nil && *j.Result == result {
		return nil
	}
	if j.State != "running" || !now.Before(j.ExpiresAt) {
		return jobs.ErrTerminal
	}
	inventoryID := ""
	if result.ReportID != "" {
		var at string
		err = tx.QueryRowContext(ctx, `SELECT json_extract(receipt,'$.snapshot_id'),json_extract(receipt,'$.received_at') FROM agent_receipts WHERE agent_id=? AND report_id=?`, agent, result.ReportID).Scan(&inventoryID, &at)
		if errors.Is(err, sql.ErrNoRows) {
			return jobs.ErrReportPending
		}
		if err != nil {
			return err
		}
		received, e := parse(at)
		if e != nil {
			return e
		}
		if j.StartedAt == nil || received.Before(*j.StartedAt) {
			return jobs.ErrInvalid
		}
	}
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE agent_jobs SET state=?,finished_at=?,result=?,inventory_id=? WHERE id=?", result.Status, stamp(now), string(data), inventoryID, j.ID); err != nil {
		return err
	}
	if err = jobEvent(ctx, tx, "agent.job."+result.Status, j.ID, agent, result); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) LocalJob(ctx context.Context, agent string) (jobs.Journal, error) {
	var j jobs.Journal
	var result sql.NullString
	err := s.db.QueryRowContext(ctx, "SELECT job_id,result FROM agent_job_journal WHERE agent_id=?", agent).Scan(&j.JobID, &result)
	if errors.Is(err, sql.ErrNoRows) {
		return j, domain.ErrNotFound
	}
	if err == nil && result.Valid {
		j.Result = &jobs.Result{}
		err = json.Unmarshal([]byte(result.String), j.Result)
	}
	return j, err
}
func (s *Store) StartLocalJob(ctx context.Context, agent, id string) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO agent_job_journal(agent_id,job_id) VALUES(?,?)", agent, id)
	return err
}
func (s *Store) SaveLocalJob(ctx context.Context, agent string, result jobs.Result) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, "UPDATE agent_job_journal SET result=? WHERE agent_id=? AND job_id=?", string(data), agent, result.JobID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return domain.ErrNotFound
	}
	return nil
}
func (s *Store) CompleteLocalJob(ctx context.Context, agent, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM agent_job_journal WHERE agent_id=? AND job_id=?", agent, id)
	return err
}
