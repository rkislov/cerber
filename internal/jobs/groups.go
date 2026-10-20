// SPDX-License-Identifier: Apache-2.0
package jobs

import "time"

const MaxGroupMembers = 500

type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Archived    bool      `json:"archived"`
	Version     int       `json:"version"`
	Members     int       `json:"members"`
	Active      int       `json:"active"`
	Revoked     int       `json:"revoked"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}
type GroupMember struct {
	AgentID   string `json:"agent_id"`
	AssetName string `json:"asset_name"`
	AssetIP   string `json:"asset_ip"`
	Revoked   bool   `json:"revoked"`
	Member    bool   `json:"member"`
}
type GroupCommand struct {
	Action          string    `json:"action"`
	ID              string    `json:"id,omitempty"`
	GroupID         string    `json:"group_id,omitempty"`
	GroupVersion    int       `json:"group_version,omitempty"`
	Name            string    `json:"name,omitempty"`
	Description     string    `json:"description,omitempty"`
	AgentIDs        []string  `json:"agent_ids,omitempty"`
	Kind            string    `json:"kind,omitempty"`
	RefreshMetadata bool      `json:"refresh_metadata,omitempty"`
	IntervalSeconds int64     `json:"interval_seconds,omitempty"`
	FirstRunAt      time.Time `json:"first_run_at,omitempty"`
}
type GroupSchedule struct {
	ID              string    `json:"id"`
	GroupID         string    `json:"group_id"`
	GroupName       string    `json:"group_name"`
	GroupVersion    int       `json:"group_version"`
	Kind            string    `json:"kind"`
	RefreshMetadata bool      `json:"refresh_metadata"`
	IntervalSeconds int64     `json:"interval_seconds"`
	NextRunAt       time.Time `json:"next_run_at"`
	Enabled         bool      `json:"enabled"`
	CreatedBy       string    `json:"created_by"`
}
type GroupRun struct {
	Sequence        int64     `json:"sequence"`
	ID              string    `json:"id"`
	GroupID         string    `json:"group_id"`
	GroupName       string    `json:"group_name"`
	ScheduleID      string    `json:"schedule_id,omitempty"`
	Kind            string    `json:"kind"`
	RefreshMetadata bool      `json:"refresh_metadata"`
	CreatedAt       time.Time `json:"created_at"`
	CreatedBy       string    `json:"created_by"`
	State           string    `json:"state"`
	Total           int       `json:"total"`
	Queued          int       `json:"queued"`
	Running         int       `json:"running"`
	Succeeded       int       `json:"succeeded"`
	Partial         int       `json:"partial"`
	Failed          int       `json:"failed"`
	Canceled        int       `json:"canceled"`
	Expired         int       `json:"expired"`
	TimedOut        int       `json:"timed_out"`
	Skipped         int       `json:"skipped"`
}

func (r *GroupRun) Evaluate() {
	switch {
	case r.Total == 0:
		r.State = "empty"
	case r.Running > 0:
		r.State = "running"
	case r.Queued > 0 && r.Queued+r.Skipped == r.Total:
		r.State = "queued"
	case r.Queued > 0:
		r.State = "running"
	case r.Skipped == r.Total:
		r.State = "skipped"
	case r.Canceled > 0 && r.Canceled+r.Skipped == r.Total:
		r.State = "canceled"
	case r.Expired > 0 && r.Expired+r.Skipped == r.Total:
		r.State = "expired"
	case r.TimedOut > 0 && r.TimedOut+r.Skipped == r.Total:
		r.State = "timed_out"
	case r.Succeeded+r.Partial == 0:
		r.State = "failed"
	case r.Succeeded == r.Total:
		r.State = "succeeded"
	default:
		r.State = "partial"
	}
}

type GroupRunMember struct {
	AgentID     string     `json:"agent_id"`
	AssetName   string     `json:"asset_name"`
	AssetIP     string     `json:"asset_ip"`
	JobID       string     `json:"job_id,omitempty"`
	State       string     `json:"state"`
	SkipReason  string     `json:"skip_reason,omitempty"`
	Code        string     `json:"code,omitempty"`
	InventoryID string     `json:"inventory_id,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
}
