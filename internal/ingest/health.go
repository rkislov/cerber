// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"fmt"
	"github.com/rkislov/cerber/internal/telemetry"
	"time"
)

const MaxHeartbeatBytes int64 = 4096

// Heartbeat is ephemeral health, not inventory. Server receipt time determines
// contact freshness; the agent clock never controls that decision.
type Heartbeat struct {
	Events           *telemetry.CollectorHealth `json:"events,omitempty"`
	SchemaVersion    int                        `json:"schema_version"`
	AgentID          string                     `json:"agent_id"`
	ObservedAt       time.Time                  `json:"observed_at"`
	Platform         string                     `json:"platform"`
	Architecture     string                     `json:"architecture"`
	QueueKnown       bool                       `json:"queue_known"`
	QueueReports     int64                      `json:"queue_reports"`
	QueueBytes       int64                      `json:"queue_bytes"`
	CollectionStatus string                     `json:"collection_status"`
	LastCollectionAt *time.Time                 `json:"last_collection_at,omitempty"`
	DeliveryStatus   string                     `json:"delivery_status"`
}

func (h Heartbeat) Validate() error {
	if h.Events != nil {
		if err := h.Events.Validate(); err != nil {
			return err
		}
	}
	if h.SchemaVersion != 1 || !Identifier(h.AgentID) || h.ObservedAt.IsZero() || h.Platform != "windows" && h.Platform != "linux" || h.Architecture != "amd64" && h.Architecture != "arm64" {
		return fmt.Errorf("invalid heartbeat metadata")
	}
	if h.QueueReports < 0 || h.QueueReports > 100 || h.QueueBytes < 0 || h.QueueBytes > 256<<20 || !h.QueueKnown && (h.QueueReports != 0 || h.QueueBytes != 0) {
		return fmt.Errorf("invalid queue health")
	}
	switch h.CollectionStatus {
	case "not_attempted", "complete", "partial", "error":
	default:
		return fmt.Errorf("invalid collection health")
	}
	switch h.DeliveryStatus {
	case "not_attempted", "ok", "error":
	default:
		return fmt.Errorf("invalid delivery health")
	}
	if h.LastCollectionAt != nil && h.LastCollectionAt.IsZero() {
		return fmt.Errorf("invalid collection time")
	}
	return nil
}
func (h Heartbeat) QueueState() string {
	if !h.QueueKnown {
		return "unknown"
	}
	if h.QueueReports >= 100 || h.QueueBytes >= 256<<20 {
		return "full"
	}
	if h.QueueReports > 0 {
		return "pending"
	}
	return "empty"
}

// TransitionKey excludes counters/timestamps to avoid a durable event per heartbeat.
func (h Heartbeat) TransitionKey() string {
	key := h.CollectionStatus + ":" + h.DeliveryStatus + ":" + h.QueueState()
	if h.Events != nil {
		key += ":" + h.Events.Key()
	}
	return key
}

type HeartbeatReceipt struct {
	AgentID    string    `json:"agent_id"`
	ObservedAt time.Time `json:"observed_at"`
	ReceivedAt time.Time `json:"received_at"`
}
type AgentStatus struct {
	AssetName         string     `json:"asset_name"`
	AssetIP           string     `json:"asset_ip"`
	AgentID           string     `json:"agent_id"`
	AssetID           string     `json:"asset_id"`
	CreatedAt         time.Time  `json:"created_at"`
	Revoked           bool       `json:"revoked"`
	LastSeenAt        *time.Time `json:"last_seen_at,omitempty"`
	LastReportAt      *time.Time `json:"last_report_at,omitempty"`
	LatestInventoryAt *time.Time `json:"latest_inventory_at,omitempty"`
	LatestInventoryID string     `json:"latest_inventory_id,omitempty"`
	LastHeartbeatAt   *time.Time `json:"last_heartbeat_at,omitempty"`
	Health            *Heartbeat `json:"health,omitempty"`
	ContactStatus     string     `json:"contact_status"`
	InventoryStatus   string     `json:"inventory_status"`
	HealthStatus      string     `json:"health_status"`
	QueueStatus       string     `json:"queue_status"`
}

func (s *AgentStatus) Evaluate(now time.Time, offlineAfter, inventoryMaxAge time.Duration) {
	s.ContactStatus = "never_seen"
	if s.LastSeenAt != nil {
		s.ContactStatus = "online"
		if now.Sub(*s.LastSeenAt) > offlineAfter {
			s.ContactStatus = "offline"
		}
	}
	if s.Revoked {
		s.ContactStatus = "revoked"
	}
	s.InventoryStatus = "missing"
	if s.LatestInventoryAt != nil && s.LatestInventoryID != "" {
		s.InventoryStatus = "fresh"
		if now.Sub(*s.LatestInventoryAt) > inventoryMaxAge {
			s.InventoryStatus = "stale"
		}
	}
	s.HealthStatus = "missing"
	s.QueueStatus = "unknown"
	if s.Health != nil && s.LastHeartbeatAt != nil {
		s.HealthStatus = "fresh"
		if now.Sub(*s.LastHeartbeatAt) > offlineAfter {
			s.HealthStatus = "stale"
		}
		if s.HealthStatus == "fresh" {
			s.QueueStatus = s.Health.QueueState()
		}
	}
}
