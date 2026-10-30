// SPDX-License-Identifier: Apache-2.0
package alerts

import (
	"context"
	"fmt"
	"github.com/rkislov/cerber/internal/ingest"
	"sync"
	"time"
)

type Policy struct {
	OfflineAfter    time.Duration `json:"offline_after"`
	InventoryMaxAge time.Duration `json:"inventory_max_age"`
}

func (p Policy) Validate() error {
	if p.OfflineAfter < time.Minute || p.OfflineAfter > 24*time.Hour || p.InventoryMaxAge < time.Minute || p.InventoryMaxAge > 365*24*time.Hour {
		return fmt.Errorf("invalid alert freshness policy")
	}
	return nil
}

type Alert struct {
	Sequence       int64      `json:"sequence"`
	ID             string     `json:"id"`
	AgentID        string     `json:"agent_id"`
	AssetID        string     `json:"asset_id"`
	AssetName      string     `json:"asset_name"`
	AssetIP        string     `json:"asset_ip"`
	Kind           string     `json:"kind"`
	Severity       string     `json:"severity"`
	RaisedAt       time.Time  `json:"raised_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	Resolution     string     `json:"resolution,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"`
	Evidence       Evidence   `json:"evidence"`
}

var Kinds = []string{"agent_offline", "inventory_stale", "event_delivery_stalled", "event_queue_growing", "event_health_stale", "sensor_no_traffic", "sensor_receive_errors", "sensor_template_errors", "sensor_policy_pending"}

func Title(kind string) string {
	if v, ok := map[string]string{"sensor_no_traffic": "Нет ожидаемого трафика экспортёра", "sensor_receive_errors": "Ошибки приёма сетевого сенсора", "sensor_template_errors": "Отсутствуют шаблоны NetFlow/IPFIX", "sensor_policy_pending": "Не применены настройки сенсора", "agent_offline": "Нет связи с агентом", "inventory_stale": "Устаревший инвентарь", "event_delivery_stalled": "Задержка доставки событий", "event_queue_growing": "Растёт очередь событий", "event_health_stale": "Устарело состояние сбора событий"}[kind]; ok {
		return v
	}
	return kind
}

type Evidence struct {
	QueueBatches     int64     `json:"queue_batches,omitempty"`
	QueueBytes       int64     `json:"queue_bytes,omitempty"`
	Detail           string    `json:"detail,omitempty"`
	ReferenceAt      time.Time `json:"reference_at"`
	ThresholdSeconds int64     `json:"threshold_seconds"`
	Missing          bool      `json:"missing"`
}

func Conditions(s ingest.AgentStatus, now time.Time, p Policy) map[string]Evidence {
	values := map[string]Evidence{}
	if s.Revoked {
		return values
	}
	seen := s.CreatedAt
	missing := s.LastSeenAt == nil
	if !missing {
		seen = *s.LastSeenAt
	}
	if now.Sub(seen) > p.OfflineAfter {
		values["agent_offline"] = Evidence{ReferenceAt: seen, ThresholdSeconds: int64(p.OfflineAfter / time.Second), Missing: missing}
	}
	if s.Health != nil && s.Health.Sensor != nil {
		return values
	}
	at := s.CreatedAt
	missing = s.LatestInventoryAt == nil || s.LatestInventoryID == ""
	if !missing {
		at = *s.LatestInventoryAt
	}
	if now.Sub(at) > p.InventoryMaxAge {
		values["inventory_stale"] = Evidence{ReferenceAt: at, ThresholdSeconds: int64(p.InventoryMaxAge / time.Second), Missing: missing}
	}
	return values
}

type Result struct {
	Scanned  int `json:"scanned"`
	Raised   int `json:"raised"`
	Resolved int `json:"resolved"`
}
type Evaluator interface {
	EvaluateAlerts(context.Context, time.Time, Policy) (Result, error)
}
type Status struct {
	LastSuccessAt          *time.Time `json:"last_success_at,omitempty"`
	Failed                 bool       `json:"failed"`
	OfflineAfterSeconds    int64      `json:"offline_after_seconds"`
	InventoryMaxAgeSeconds int64      `json:"inventory_max_age_seconds"`
	IntervalSeconds        int64      `json:"interval_seconds"`
}
type Monitor struct {
	mu       sync.Mutex
	status   Status
	Policy   Policy
	Interval time.Duration
}

func (m *Monitor) Snapshot() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	if s.LastSuccessAt != nil {
		v := *s.LastSuccessAt
		s.LastSuccessAt = &v
	}
	s.OfflineAfterSeconds = int64(m.Policy.OfflineAfter / time.Second)
	s.InventoryMaxAgeSeconds = int64(m.Policy.InventoryMaxAge / time.Second)
	s.IntervalSeconds = int64(m.Interval / time.Second)
	return s
}
func (m *Monitor) Run(ctx context.Context, store Evaluator, logError func(error)) {
	for {
		if ctx.Err() != nil {
			return
		}
		now := time.Now().UTC()
		_, err := store.EvaluateAlerts(ctx, now, m.Policy)
		m.mu.Lock()
		m.status.Failed = err != nil
		if err == nil {
			m.status.LastSuccessAt = &now
		}
		m.mu.Unlock()
		if err != nil && ctx.Err() == nil && logError != nil {
			logError(err)
		}
		timer := time.NewTimer(m.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
