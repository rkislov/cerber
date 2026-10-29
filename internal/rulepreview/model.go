// SPDX-License-Identifier: Apache-2.0
package rulepreview

import (
	"github.com/rkislov/cerber/internal/rulepolicy"
	"github.com/rkislov/cerber/internal/telemetry"
	"time"
)

type Request struct {
	Rule     string            `json:"rule"`
	Config   rulepolicy.Config `json:"config"`
	EventIDs []string          `json:"event_ids"`
}
type Row struct {
	EventID          string                `json:"event_id"`
	Sequence         int64                 `json:"sequence"`
	Reason           string                `json:"reason"`
	HistoryTruncated bool                  `json:"history_truncated"`
	Findings         []telemetry.Detection `json:"findings"`
}
type Result struct {
	Truncated      bool              `json:"truncated"`
	DryRun         bool              `json:"dry_run"`
	At             time.Time         `json:"at"`
	Policy         rulepolicy.Config `json:"policy"`
	ActiveRevision int64             `json:"active_revision"`
	IOCRevision    string            `json:"ioc_revision,omitempty"`
	Rows           []Row             `json:"rows"`
	Limitations    string            `json:"limitations"`
}
