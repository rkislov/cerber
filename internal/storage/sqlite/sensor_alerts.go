// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/sensorstate"
	"strings"
	"time"
)

func sensorConditions(ctx context.Context, tx *sql.Tx, a ingest.AgentStatus, now time.Time, out map[string]alerts.Evidence) error {
	if a.Health == nil || a.Health.Sensor == nil {
		return nil
	}
	// Sensor freshness follows heartbeat, not inventory contacts or quiet inputs.
	delete(out, "agent_offline")
	if a.Revoked {
		return nil
	}
	p, e := sensorPolicy(ctx, tx, a.AgentID)
	if e != nil {
		return e
	}
	c := p.MonitorConfig()
	if !c.Enabled {
		_, e = tx.ExecContext(ctx, "DELETE FROM event_delivery_observations WHERE agent_id=?", a.AgentID)
		return e
	}
	ref := a.CreatedAt
	if a.LastHeartbeatAt != nil {
		ref = *a.LastHeartbeatAt
	}
	if now.Sub(ref) > time.Duration(c.OfflineSeconds)*time.Second {
		out["agent_offline"] = alerts.Evidence{ReferenceAt: ref, ThresholdSeconds: int64(c.OfflineSeconds), Detail: "Сетевой сенсор не передаёт heartbeat"}
		return nil
	}
	s := a.Health.Sensor
	if now.Sub(s.ObservedAt) > 5*time.Minute || s.ObservedAt.After(now.Add(5*time.Minute)) {
		out["event_health_stale"] = alerts.Evidence{ReferenceAt: s.ObservedAt, ThresholdSeconds: 300, Detail: "Состояние сенсора устарело либо его часы расходятся с сервером более чем на пять минут"}
		return nil
	}
	if s.ConfigError != "" || (p.Revision > s.AppliedRevision && now.Sub(p.UpdatedAt) > time.Duration(c.PendingSeconds)*time.Second) {
		out["sensor_policy_pending"] = alerts.Evidence{ReferenceAt: p.UpdatedAt, ThresholdSeconds: int64(c.PendingSeconds), Detail: fmt.Sprintf("Конфигурация сенсора: сохранена версия %d, применена %d; код: %s; вход: %s", p.Revision, s.AppliedRevision, s.ConfigError, s.ConfigErrorInput)}
	}
	if e = sensorQueueConditions(ctx, tx, a, now, c, out); e != nil {
		return e
	}

	end := now.Truncate(time.Minute).Unix()
	rows, e := tx.QueryContext(ctx, `SELECT input_id,SUM(messages),SUM(rejected),SUM(unknown_sets) FROM sensor_samples WHERE agent_id=? AND input_id!='' AND step=60 AND bucket>=? AND bucket<? GROUP BY input_id`, a.AgentID, end-int64(c.WindowSeconds), end)
	if e != nil {
		return e
	}
	var failures, templates []string
	active := map[string]bool{}
	for _, i := range s.Inputs {
		active[i.ID] = i.Enabled
	}
	for rows.Next() {
		var input string
		var messages, rejected, unknown int64
		if e = rows.Scan(&input, &messages, &rejected, &unknown); e != nil {
			rows.Close()
			return e
		}
		if !active[input] {
			continue
		}
		if messages >= int64(c.MinMessages) && float64(rejected)*100/float64(messages) >= float64(c.ErrorPercent) {
			failures = append(failures, fmt.Sprintf("%s: %d из %d сообщений с отказом/потерями", input, rejected, messages))
		}
		if unknown >= int64(c.UnknownSets) {
			templates = append(templates, fmt.Sprintf("%s: %d наборов без доступного шаблона", input, unknown))
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	evidence := func(detail string) alerts.Evidence {
		return alerts.Evidence{ReferenceAt: time.Unix(end-int64(c.WindowSeconds), 0).UTC(), ThresholdSeconds: int64(c.WindowSeconds), Detail: detail}
	}
	if len(failures) > 0 {
		out["sensor_receive_errors"] = evidence(strings.Join(failures, "; "))
	}
	if len(templates) > 0 {
		out["sensor_template_errors"] = evidence(strings.Join(templates, "; "))
	}
	if p.Monitor != nil && len(c.Watches) > 0 && s.MonitoringVersion != 1 {
		out["sensor_policy_pending"] = evidence("Сенсор не поддерживает отчёты ожидаемых экспортёров: обновите cerber-sensor")
	}
	if p.Monitor != nil && s.MonitoringVersion == 1 && s.AppliedRevision >= p.Monitor.Revision {
		observed := map[string]sensorstate.WatchStatus{}
		for _, w := range s.Watches {
			observed[sensorstate.WatchKey(w.Input, w.Peer)] = w
		}
		var silent []string
		for _, w := range c.Watches {
			if !active[w.Input] {
				continue
			}
			seen, ok := observed[sensorstate.WatchKey(w.Input, w.Peer)]
			if !ok {
				if now.Sub(p.Monitor.UpdatedAt) > time.Duration(c.PendingSeconds)*time.Second {
					out["event_health_stale"] = evidence("Сенсор не передал состояние ожидаемого источника " + w.Input + " / " + w.Peer)
				}
				continue
			}
			at := seen.Since
			if seen.LastSeen != nil {
				at = *seen.LastSeen
			}
			if at.Before(p.Monitor.UpdatedAt) {
				at = p.Monitor.UpdatedAt
			}
			if now.Sub(at) > time.Duration(w.SilenceSeconds)*time.Second {
				peer := w.Peer
				if peer == "" {
					peer = "все разрешённые экспортёры"
				}
				silent = append(silent, fmt.Sprintf("%s / %s: нет принятых сообщений %d мин (порог %d мин)", w.Input, peer, int(now.Sub(at).Minutes()), w.SilenceSeconds/60))
			}
		}
		if len(silent) > 0 {
			out["sensor_no_traffic"] = evidence(strings.Join(silent, "; "))
		}
	}
	return nil
}

func sensorQueueConditions(ctx context.Context, tx *sql.Tx, a ingest.AgentStatus, now time.Time, c sensorstate.MonitorConfig, out map[string]alerts.Evidence) error {
	q := a.Health.Events
	if q == nil || !q.QueueKnown {
		out["event_health_stale"] = alerts.Evidence{ReferenceAt: a.Health.Sensor.ObservedAt, Detail: "Сенсор не передал состояние очереди"}
		return nil
	}
	if now.Sub(q.ObservedAt) > 5*time.Minute || q.ObservedAt.After(now.Add(5*time.Minute)) {
		out["event_health_stale"] = alerts.Evidence{ReferenceAt: q.ObservedAt, ThresholdSeconds: 300, Detail: "Нет свежего состояния очереди сенсора"}
		return nil
	}
	if q.QueueBatches == 0 {
		_, e := tx.ExecContext(ctx, "DELETE FROM event_delivery_observations WHERE agent_id=?", a.AgentID)
		return e
	}
	var first string
	var base int64
	e := tx.QueryRowContext(ctx, "SELECT first_at,base_batches FROM event_delivery_observations WHERE agent_id=?", a.AgentID).Scan(&first, &base)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	at := now
	if e == nil {
		at, e = parse(first)
		if e != nil {
			return e
		}
	}
	if first == "" || at.Before(a.Health.Sensor.StartedAt) {
		at = now
		base = q.QueueBatches
		if _, e = tx.ExecContext(ctx, "INSERT INTO event_delivery_observations VALUES(?,?,?) ON CONFLICT(agent_id) DO UPDATE SET first_at=excluded.first_at,base_batches=excluded.base_batches", a.AgentID, stamp(now), base); e != nil {
			return e
		}
	}
	mature := now.Sub(at) >= time.Duration(c.WindowSeconds)*time.Second
	ev := alerts.Evidence{ReferenceAt: at, ThresholdSeconds: int64(c.WindowSeconds), QueueBatches: q.QueueBatches, QueueBytes: q.QueueBytes}
	if q.QueueBatches >= c.QueueBatches || q.QueueBytes >= c.QueueBytes || mature && q.QueueBatches > base {
		ev.Detail = "Очередь сенсора достигла заданного порога или выросла за окно непрерывного наблюдения"
		out["event_queue_growing"] = ev
	}
	if mature && (q.LastDeliveryAt == nil || now.Sub(*q.LastDeliveryAt) >= time.Duration(c.WindowSeconds)*time.Second) {
		ev.Detail = "В очереди сенсора есть события, подтверждения доставки отсутствуют дольше заданного окна"
		out["event_delivery_stalled"] = ev
	}
	return nil
}
