// SPDX-License-Identifier: Apache-2.0
// Package jobs defines the allowlisted agent work protocol and interval schedules.
package jobs

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrInvalid = errors.New("invalid job request")
var ErrTerminal = errors.New("job no longer running")
var ErrReportPending = errors.New("job report not received")

const Lease = 10 * time.Minute
const QueueTTL = 24 * time.Hour

func ValidKind(kind string) bool { return kind == "inventory" || kind == "updates" }

type Job struct {
	GroupRunID      string     `json:"group_run_id,omitempty"`
	Sequence        int64      `json:"sequence"`
	ID              string     `json:"id"`
	AgentID         string     `json:"agent_id"`
	AssetName       string     `json:"asset_name"`
	AssetIP         string     `json:"asset_ip"`
	ScheduleID      string     `json:"schedule_id,omitempty"`
	Kind            string     `json:"kind"`
	RefreshMetadata bool       `json:"refresh_metadata"`
	State           string     `json:"state"`
	CreatedAt       time.Time  `json:"created_at"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	ExpiresAt       time.Time  `json:"expires_at"`
	CreatedBy       string     `json:"created_by"`
	Result          *Result    `json:"result,omitempty"`
	InventoryID     string     `json:"inventory_id,omitempty"`
}
type Result struct {
	JobID    string `json:"job_id"`
	Status   string `json:"status"`
	Code     string `json:"code"`
	ReportID string `json:"report_id,omitempty"`
}

func (r Result) Validate() error {
	if r.Status != "succeeded" && r.Status != "partial" && r.Status != "failed" {
		return ErrInvalid
	}
	switch r.Code {
	case "complete", "partial_coverage", "collection_failed", "queue_full", "interrupted", "unsupported_platform":
	default:
		return ErrInvalid
	}
	if r.Status == "succeeded" && (r.Code != "complete" || r.ReportID == "") {
		return ErrInvalid
	}
	if r.Status == "partial" && (r.Code != "partial_coverage" || r.ReportID == "") {
		return ErrInvalid
	}
	if r.Status == "failed" && (r.Code == "complete" || r.Code == "partial_coverage") {
		return ErrInvalid
	}
	return nil
}

type Schedule struct {
	ID              string    `json:"id"`
	AgentID         string    `json:"agent_id"`
	AssetName       string    `json:"asset_name"`
	AssetIP         string    `json:"asset_ip"`
	Kind            string    `json:"kind"`
	RefreshMetadata bool      `json:"refresh_metadata"`
	IntervalSeconds int64     `json:"interval_seconds"`
	NextRunAt       time.Time `json:"next_run_at"`
	Enabled         bool      `json:"enabled"`
	CreatedBy       string    `json:"created_by"`
}
type Command struct {
	GroupRunID      string    `json:"-"`
	Scheduled       bool      `json:"-"`
	Action          string    `json:"action"`
	ID              string    `json:"id,omitempty"`
	AgentID         string    `json:"agent_id,omitempty"`
	Kind            string    `json:"kind,omitempty"`
	RefreshMetadata bool      `json:"refresh_metadata,omitempty"`
	IntervalSeconds int64     `json:"interval_seconds,omitempty"`
	FirstRunAt      time.Time `json:"first_run_at,omitempty"`
}
type Journal struct {
	JobID  string
	Result *Result
}
type Scheduler interface {
	AdvanceJobs(context.Context, time.Time) error
}

type Status struct {
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	Failed        bool       `json:"failed"`
}
type Monitor struct {
	mu     sync.Mutex
	status Status
}

func (m *Monitor) Snapshot() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	if s.LastSuccessAt != nil {
		at := *s.LastSuccessAt
		s.LastSuccessAt = &at
	}
	return s
}
func (m *Monitor) Run(ctx context.Context, store Scheduler, logError func(error)) {
	for {
		if ctx.Err() != nil {
			return
		}
		now := time.Now().UTC()
		err := store.AdvanceJobs(ctx, now)
		m.mu.Lock()
		m.status.Failed = err != nil
		if err == nil {
			m.status.LastSuccessAt = &now
		}
		m.mu.Unlock()
		if err != nil && ctx.Err() == nil && logError != nil {
			logError(err)
		}
		timer := time.NewTimer(15 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
