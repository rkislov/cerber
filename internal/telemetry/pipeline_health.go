// SPDX-License-Identifier: Apache-2.0
package telemetry

import "time"

type PipelineAlert struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"`
	Severity string    `json:"severity"`
	Detail   string    `json:"detail"`
	RaisedAt time.Time `json:"raised_at"`
}
type PipelineHealth struct {
	DiskAvailable        uint64          `json:"disk_available"`
	DiskTotal            uint64          `json:"disk_total"`
	At                   time.Time       `json:"at"`
	SampleSeconds        float64         `json:"sample_seconds"`
	ReceivedPerSecond    float64         `json:"received_per_second"`
	ProcessedPerSecond   float64         `json:"processed_per_second"`
	PendingNormalization int64           `json:"pending_normalization"`
	PendingCorrelation   int64           `json:"pending_correlation"`
	OldestPendingSeconds float64         `json:"oldest_pending_seconds"`
	JournalBytes         int64           `json:"journal_bytes"`
	JournalMaxBytes      int64           `json:"journal_max_bytes"`
	JournalPercent       float64         `json:"journal_percent"`
	Retention            RetentionStatus `json:"retention"`
	Alerts               []PipelineAlert `json:"alerts"`
}
