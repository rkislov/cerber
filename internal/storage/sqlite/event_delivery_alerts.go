// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/ingest"
	"time"
)

func eventDeliveryConditions(ctx context.Context, tx *sql.Tx, a ingest.AgentStatus, now time.Time, out map[string]alerts.Evidence) error {
	reset := func() error {
		_, e := tx.ExecContext(ctx, "DELETE FROM event_delivery_observations WHERE agent_id=?", a.AgentID)
		return e
	}
	if a.Revoked || a.Health == nil || a.Health.Events == nil || !a.Health.Events.Enabled || a.LastHeartbeatAt == nil || now.Sub(*a.LastHeartbeatAt) > 5*time.Minute {
		return reset()
	}
	h := a.Health.Events
	if now.Sub(h.ObservedAt) > 5*time.Minute || h.ObservedAt.After(now.Add(5*time.Minute)) {
		out["event_health_stale"] = alerts.Evidence{ReferenceAt: h.ObservedAt, ThresholdSeconds: 300, Detail: "Агент на связи, но состояние сборщика устарело либо его часы опережают сервер более чем на пять минут"}
		return nil
	}
	if !h.QueueKnown || h.QueueBatches == 0 {
		return reset()
	}
	var first string
	var base int64
	e := tx.QueryRowContext(ctx, "SELECT first_at,base_batches FROM event_delivery_observations WHERE agent_id=?", a.AgentID).Scan(&first, &base)
	if errors.Is(e, sql.ErrNoRows) {
		_, e = tx.ExecContext(ctx, "INSERT INTO event_delivery_observations VALUES(?,?,?)", a.AgentID, stamp(now), h.QueueBatches)
		return e
	}
	if e != nil {
		return e
	}
	at, e := parse(first)
	if e != nil {
		return e
	}
	evidence := alerts.Evidence{ReferenceAt: at, ThresholdSeconds: 300, QueueBatches: h.QueueBatches, QueueBytes: h.QueueBytes}
	if now.Sub(at) >= 5*time.Minute && (h.LastDeliveryAt == nil || now.Sub(*h.LastDeliveryAt) >= 5*time.Minute) {
		evidence.Detail = "Есть недоставленные пакеты, подтверждение доставки отсутствует более пяти минут"
		out["event_delivery_stalled"] = evidence
	}
	if now.Sub(at) >= 5*time.Minute && h.QueueBatches > base || h.QueueBatches >= 500 || h.QueueBytes >= 128<<20 {
		evidence.Detail = "Очередь выросла после начала наблюдения (не менее пяти минут) либо достигла половины локального лимита"
		out["event_queue_growing"] = evidence
	}
	return nil
}
