// SPDX-License-Identifier: Apache-2.0
package suricatarules

import (
	"context"
	"time"
)

// A canary group is a subset of the policy's target group. Membership and every
// sensor's confirmed recovery package are snapshotted before any assignment.
type RolloutConfig struct {
	CanaryGroupID      string `json:"canary_group_id"`
	ObservationSeconds int    `json:"observation_seconds"`
	TimeoutSeconds     int    `json:"timeout_seconds"`
	MaxDropPercent     int    `json:"max_drop_percent"`
	MaxQueueMiB        int    `json:"max_queue_mib"`
}

type RolloutMember struct {
	AgentID            string    `json:"agent_id"`
	Name               string    `json:"name"`
	Phase              string    `json:"phase"`
	PreviousID         string    `json:"previous_id"`
	OriginalRevision   int64     `json:"original_revision"`
	AssignmentRevision int64     `json:"assignment_revision"`
	RollbackRevision   int64     `json:"rollback_revision"`
	State              string    `json:"state"`
	Error              string    `json:"error,omitempty"`
	HealthySince       time.Time `json:"healthy_since"`
	LastHeartbeat      time.Time `json:"last_heartbeat"`
	LastObserved       time.Time `json:"last_observed"`
	LastCapture        time.Time `json:"last_capture"`
	Samples            int       `json:"samples"`
	Packets            uint64    `json:"packets"`
	Dropped            uint64    `json:"dropped"`
	Uptime             uint64    `json:"uptime"`
	SensorStarted      time.Time `json:"sensor_started"`
	Interface          string    `json:"interface"`
	CaptureMode        string    `json:"capture_mode"`
	QueueBytes         int64     `json:"queue_bytes"`
	DropPercent        float64   `json:"drop_percent"`
}

type Rollout struct {
	ID             string          `json:"id"`
	GroupID        string          `json:"group_id"`
	PolicyRevision int64           `json:"policy_revision"`
	CandidateID    string          `json:"candidate_id"`
	PreviousID     string          `json:"previous_id,omitempty"`
	State          string          `json:"state"`
	Error          string          `json:"error,omitempty"`
	Config         RolloutConfig   `json:"config"`
	StartedAt      time.Time       `json:"started_at"`
	StageStartedAt time.Time       `json:"stage_started_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	Members        []RolloutMember `json:"members"`
}

func RolloutHolds(state string) bool {
	return state == "canary" || state == "fleet" || state == "rolling_back" || state == "rollback_failed"
}

type RolloutStore interface {
	AdvanceSuricataRollouts(context.Context, time.Time) error
}

// Health supervision must not wait for ET Open HTTP downloads.
func RunRollouts(ctx context.Context, s RolloutStore, onError func(error)) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		work, cancel := context.WithTimeout(ctx, 8*time.Second)
		err := s.AdvanceSuricataRollouts(work, time.Now().UTC())
		cancel()
		if err != nil && ctx.Err() == nil && onError != nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
