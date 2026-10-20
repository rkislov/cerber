// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"

	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/jobs"
)

func (s *Store) GroupSchedules(ctx context.Context, group, after string, limit int) ([]jobs.GroupSchedule, error) {
	if limit < 1 || limit > 101 {
		return nil, jobs.ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, `SELECT s.id,s.group_id,g.name,g.version,s.kind,s.refresh_metadata,s.interval_seconds,s.next_run_at,s.enabled,s.created_by FROM agent_group_schedules s JOIN agent_groups g ON g.id=s.group_id WHERE (?='' OR s.group_id=?) AND s.id>? ORDER BY s.id LIMIT ?`, group, group, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []jobs.GroupSchedule{}
	for rows.Next() {
		var v jobs.GroupSchedule
		var at string
		if err = rows.Scan(&v.ID, &v.GroupID, &v.GroupName, &v.GroupVersion, &v.Kind, &v.RefreshMetadata, &v.IntervalSeconds, &at, &v.Enabled, &v.CreatedBy); err != nil {
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
func (s *Store) GroupRuns(ctx context.Context, group string, before int64, limit int) ([]jobs.GroupRun, error) {
	return s.groupRuns(ctx, group, before, "", limit)
}
func (s *Store) AgentGroupRun(ctx context.Context, id string) (jobs.GroupRun, error) {
	items, err := s.groupRuns(ctx, "", 0, id, 1)
	if err != nil {
		return jobs.GroupRun{}, err
	}
	if len(items) == 0 {
		return jobs.GroupRun{}, domain.ErrNotFound
	}
	return items[0], nil
}
func (s *Store) groupRuns(ctx context.Context, group string, before int64, id string, limit int) ([]jobs.GroupRun, error) {
	if before < 0 || limit < 1 || limit > 101 {
		return nil, jobs.ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, `WITH page AS (SELECT * FROM agent_group_runs WHERE (?='' OR group_id=?) AND (?=0 OR sequence<?) AND (?='' OR id=?) ORDER BY sequence DESC LIMIT ?)
 SELECT r.sequence,r.id,r.group_id,r.group_name,COALESCE(r.schedule_id,''),r.kind,r.refresh_metadata,r.created_at,r.created_by,
 count(m.agent_id),
 sum(CASE WHEN j.state='queued' THEN 1 ELSE 0 END),sum(CASE WHEN j.state='running' THEN 1 ELSE 0 END),
 sum(CASE WHEN j.state='succeeded' THEN 1 ELSE 0 END),sum(CASE WHEN j.state='partial' THEN 1 ELSE 0 END),
 sum(CASE WHEN j.state='failed' THEN 1 ELSE 0 END),sum(CASE WHEN j.state='canceled' THEN 1 ELSE 0 END),
 sum(CASE WHEN j.state='expired' THEN 1 ELSE 0 END),sum(CASE WHEN j.state='timed_out' THEN 1 ELSE 0 END),
 sum(CASE WHEN m.skip_reason<>'' THEN 1 ELSE 0 END)
 FROM page r LEFT JOIN agent_group_run_members m ON m.run_id=r.id LEFT JOIN agent_jobs j ON j.id=m.job_id
 GROUP BY r.sequence ORDER BY r.sequence DESC`, group, group, before, before, id, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []jobs.GroupRun{}
	for rows.Next() {
		var v jobs.GroupRun
		var at string
		if err = rows.Scan(&v.Sequence, &v.ID, &v.GroupID, &v.GroupName, &v.ScheduleID, &v.Kind, &v.RefreshMetadata, &at, &v.CreatedBy, &v.Total, &v.Queued, &v.Running, &v.Succeeded, &v.Partial, &v.Failed, &v.Canceled, &v.Expired, &v.TimedOut, &v.Skipped); err != nil {
			return nil, err
		}
		v.CreatedAt, err = parse(at)
		if err != nil {
			return nil, err
		}
		v.Evaluate()
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) GroupRunMembers(ctx context.Context, id, after string, limit int) ([]jobs.GroupRunMember, error) {
	if limit < 1 || limit > 101 {
		return nil, jobs.ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, `SELECT m.agent_id,m.asset_name,m.asset_ip,COALESCE(m.job_id,''),COALESCE(j.state,'skipped'),m.skip_reason,COALESCE(json_extract(j.result,'$.code'),''),COALESCE(j.inventory_id,''),j.started_at,j.finished_at FROM agent_group_run_members m LEFT JOIN agent_jobs j ON j.id=m.job_id WHERE m.run_id=? AND m.agent_id>? ORDER BY m.agent_id LIMIT ?`, id, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []jobs.GroupRunMember{}
	for rows.Next() {
		var v jobs.GroupRunMember
		var started, finished sql.NullString
		if err = rows.Scan(&v.AgentID, &v.AssetName, &v.AssetIP, &v.JobID, &v.State, &v.SkipReason, &v.Code, &v.InventoryID, &started, &finished); err != nil {
			return nil, err
		}
		if started.Valid {
			at, e := parse(started.String)
			if e != nil {
				return nil, e
			}
			v.StartedAt = &at
		}
		if finished.Valid {
			at, e := parse(finished.String)
			if e != nil {
				return nil, e
			}
			v.FinishedAt = &at
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
