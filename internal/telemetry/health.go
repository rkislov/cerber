// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"fmt"
	"strings"
	"time"
)

type SourceHealth struct {
	Source     string     `json:"source"`
	State      string     `json:"state"`
	Code       string     `json:"code,omitempty"`
	LastReadAt *time.Time `json:"last_read_at,omitempty"`
}
type CollectorHealth struct {
	Enabled        bool           `json:"enabled"`
	ObservedAt     time.Time      `json:"observed_at"`
	Sources        []SourceHealth `json:"sources"`
	QueueKnown     bool           `json:"queue_known"`
	QueueBatches   int64          `json:"queue_batches"`
	QueueBytes     int64          `json:"queue_bytes"`
	Delivery       string         `json:"delivery"`
	LastDeliveryAt *time.Time     `json:"last_delivery_at,omitempty"`
}

func (h CollectorHealth) Validate() error {
	if h.ObservedAt.IsZero() || len(h.Sources) > 4 || h.Enabled && len(h.Sources) == 0 || !h.Enabled && len(h.Sources) != 0 {
		return fmt.Errorf("invalid event health")
	}
	if h.QueueBatches < 0 || h.QueueBatches > 1000 || h.QueueBytes < 0 || h.QueueBytes > 256<<20 || !h.QueueKnown && (h.QueueBatches != 0 || h.QueueBytes != 0) {
		return fmt.Errorf("invalid event spool health")
	}
	switch h.Delivery {
	case "not_attempted", "idle", "ok", "error":
	default:
		return fmt.Errorf("invalid event delivery health")
	}
	if h.LastDeliveryAt != nil && h.LastDeliveryAt.IsZero() {
		return fmt.Errorf("invalid event delivery time")
	}
	seen := map[string]bool{}
	for _, s := range h.Sources {
		if !ValidSource(s.Source) || seen[s.Source] {
			return fmt.Errorf("invalid event source health")
		}
		seen[s.Source] = true
		switch s.State {
		case "not_attempted", "ok":
			if s.Code != "" {
				return fmt.Errorf("unexpected event source error")
			}
		case "error":
			if s.Code != "source_read_failed" && s.Code != "spool_error" {
				return fmt.Errorf("invalid event error")
			}
		case "blocked":
			if s.Code != "spool_full" {
				return fmt.Errorf("invalid event backpressure")
			}
		default:
			return fmt.Errorf("invalid event source state")
		}
		if s.LastReadAt != nil && s.LastReadAt.IsZero() {
			return fmt.Errorf("invalid event source time")
		}
	}
	return nil
}
func (h CollectorHealth) Key() string {
	out := []string{fmt.Sprint(h.Enabled), h.Delivery}
	if !h.QueueKnown {
		out = append(out, "unknown")
	} else if h.QueueBatches >= 1000 || h.QueueBytes >= 256<<20 {
		out = append(out, "full")
	} else if h.QueueBatches > 0 {
		out = append(out, "pending")
	} else {
		out = append(out, "empty")
	}
	for _, s := range h.Sources {
		out = append(out, s.Source+":"+s.State+":"+s.Code)
	}
	return strings.Join(out, ":")
}

// Clone prevents heartbeat readers sharing mutable slices with collection updates.
func (h CollectorHealth) Clone() CollectorHealth {
	h.Sources = append([]SourceHealth(nil), h.Sources...)
	if h.LastDeliveryAt != nil {
		at := *h.LastDeliveryAt
		h.LastDeliveryAt = &at
	}
	for i := range h.Sources {
		if h.Sources[i].LastReadAt != nil {
			at := *h.Sources[i].LastReadAt
			h.Sources[i].LastReadAt = &at
		}
	}
	return h
}
