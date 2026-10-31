// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/cerber/internal/event"
	"github.com/rkislov/cerber/internal/ingest"
	"time"
)

func recordReportContact(ctx context.Context, tx *sql.Tx, id, snapshot string, collected, received time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO agent_status(agent_id,last_seen_at,last_report_at,latest_inventory_at,latest_inventory_id) VALUES(?,?,?,?,?)
 ON CONFLICT(agent_id) DO UPDATE SET last_seen_at=MAX(agent_status.last_seen_at,excluded.last_seen_at),
 last_report_at=MAX(COALESCE(agent_status.last_report_at,''),excluded.last_report_at),
 latest_inventory_id=CASE WHEN excluded.latest_inventory_at>COALESCE(agent_status.latest_inventory_at,'') THEN excluded.latest_inventory_id ELSE agent_status.latest_inventory_id END,
 latest_inventory_at=MAX(COALESCE(agent_status.latest_inventory_at,''),excluded.latest_inventory_at)`, id, stamp(received), stamp(received), stamp(collected), snapshot)
	return err
}

// Backfill bounded pages of metadata; historical report arrival cannot make an
// older collected snapshot replace a newer observation.
func backfillAgentStatus(ctx context.Context, tx *sql.Tx) error {
	after := ""
	for {
		rows, err := tx.QueryContext(ctx, `SELECT a.id,
 (SELECT receipt FROM agent_receipts r WHERE r.agent_id=a.id ORDER BY julianday(json_extract(receipt,'$.received_at')) DESC,r.rowid DESC LIMIT 1),
 (SELECT i.id FROM agent_receipts r JOIN inventories i ON i.id=json_extract(r.receipt,'$.snapshot_id') WHERE r.agent_id=a.id ORDER BY i.collected_at DESC,i.sequence ASC LIMIT 1),
 (SELECT i.collected_at FROM agent_receipts r JOIN inventories i ON i.id=json_extract(r.receipt,'$.snapshot_id') WHERE r.agent_id=a.id ORDER BY i.collected_at DESC,i.sequence ASC LIMIT 1)
 FROM agents a WHERE a.id>? ORDER BY a.id LIMIT 1000`, after)
		if err != nil {
			return err
		}
		type item struct {
			id                    string
			receipt, snapshot, at sql.NullString
		}
		items := []item{}
		for rows.Next() {
			var v item
			if err = rows.Scan(&v.id, &v.receipt, &v.snapshot, &v.at); err != nil {
				break
			}
			items = append(items, v)
		}
		scanErr := rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if scanErr != nil {
			return scanErr
		}
		if len(items) == 0 {
			return nil
		}
		for _, v := range items {
			after = v.id
			if !v.receipt.Valid {
				continue
			}
			var receipt ingest.Receipt
			if err = json.Unmarshal([]byte(v.receipt.String), &receipt); err != nil {
				return err
			}
			if !v.snapshot.Valid || !v.at.Valid || receipt.ReceivedAt.IsZero() {
				return fmt.Errorf("invalid historical report metadata")
			}
			at, err := parse(v.at.String)
			if err != nil {
				return err
			}
			if err = recordReportContact(ctx, tx, v.id, v.snapshot.String, at, receipt.ReceivedAt); err != nil {
				return err
			}
		}
	}
}
func (s *Store) AcceptHeartbeat(ctx context.Context, id, hash string, h ingest.Heartbeat) (ingest.HeartbeatReceipt, error) {
	var receipt ingest.HeartbeatReceipt
	if h.AgentID != id {
		return receipt, ErrUnauthorized
	}
	if err := h.Validate(); err != nil {
		return receipt, err
	}
	data, err := json.Marshal(h)
	if err != nil {
		return receipt, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return receipt, err
	}
	defer tx.Rollback()
	asset, err := agentBinding(ctx, tx, id, hash)
	if err != nil {
		return receipt, err
	}
	var previous string
	err = tx.QueryRowContext(ctx, "SELECT payload FROM agent_heartbeats WHERE agent_id=?", id).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return receipt, err
	}
	var old ingest.Heartbeat
	changed := previous == ""
	if !changed {
		if err = json.Unmarshal([]byte(previous), &old); err != nil {
			return receipt, err
		}
		changed = old.TransitionKey() != h.TransitionKey()
	}
	now := time.Now().UTC()
	receipt = ingest.HeartbeatReceipt{AgentID: id, ObservedAt: h.ObservedAt, ReceivedAt: now}
	if h.Sensor != nil && h.Sensor.Rules != nil {
		a, e := suricataAssignment(ctx, tx, id)
		if e != nil {
			return receipt, e
		}
		if a.Revision > 0 {
			receipt.Suricata = &a
		}
		if old.Sensor == nil || old.Sensor.Rules == nil || *old.Sensor.Rules != *h.Sensor.Rules {
			// Heartbeat timestamps change during steady state; only lifecycle transitions enter history.
			if old.Sensor == nil || old.Sensor.Rules == nil || old.Sensor.Rules.State != h.Sensor.Rules.State || old.Sensor.Rules.Revision != h.Sensor.Rules.Revision || old.Sensor.Rules.AppliedID != h.Sensor.Rules.AppliedID || old.Sensor.Rules.Error != h.Sensor.Rules.Error {
				if e = suricataHistory(ctx, tx, id, "suricata.status", h.Sensor.Rules); e != nil {
					return receipt, e
				}
			}
		}
	}
	// Duplicate/out-of-order sensor observations must not double-count cumulative counters.
	duplicate := h.Sensor != nil && old.Sensor != nil && !h.Sensor.ObservedAt.After(old.Sensor.ObservedAt)
	if duplicate {
		policy, e := sensorPolicy(ctx, tx, id)
		if e != nil {
			return receipt, e
		}
		if policy.Revision > 0 {
			receipt.SensorPolicy = &policy
		}
		return receipt, tx.Commit()
	}
	if err = recordSensorHistory(ctx, tx, id, h, old, now); err != nil {
		return receipt, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO agent_heartbeats(agent_id,received_at,payload) VALUES(?,?,?) ON CONFLICT(agent_id) DO UPDATE SET received_at=excluded.received_at,payload=excluded.payload`, id, stamp(now), string(data)); err != nil {
		return receipt, err
	}
	if err = reconcileSuricataGroup(ctx, tx, id, h); err != nil {
		return receipt, err
	}
	if h.Sensor != nil && h.Sensor.Rules != nil {
		a, e := suricataAssignment(ctx, tx, id)
		if e != nil {
			return receipt, e
		}
		if a.Revision > 0 {
			receipt.Suricata = &a
		}
	}

	if _, err = tx.ExecContext(ctx, `INSERT INTO agent_status(agent_id,last_seen_at) VALUES(?,?) ON CONFLICT(agent_id) DO UPDATE SET last_seen_at=MAX(agent_status.last_seen_at,excluded.last_seen_at)`, id, stamp(now)); err != nil {
		return receipt, err
	}
	if changed {
		e, err := event.New("agent.health_changed", asset, map[string]any{"agent_id": id, "asset_id": asset, "collection_status": h.CollectionStatus, "delivery_status": h.DeliveryStatus, "queue_status": h.QueueState(), "received_at": now})
		if err != nil {
			return receipt, err
		}
		e.Source = "agent:" + id
		if err = appendEvent(ctx, tx, e); err != nil {
			return receipt, err
		}
	}
	if h.Sensor != nil {
		policy, e := sensorPolicy(ctx, tx, id)
		if e != nil {
			return receipt, e
		}
		if policy.Revision > 0 {
			receipt.SensorPolicy = &policy
		}
	}
	return receipt, tx.Commit()
}

type rowsQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (s *Store) AgentStatuses(ctx context.Context, asset, after string, limit int) ([]ingest.AgentStatus, error) {
	return agentStatuses(ctx, s.db, asset, after, limit)
}
func agentStatuses(ctx context.Context, q rowsQuerier, asset, after string, limit int, sensorOnly ...bool) ([]ingest.AgentStatus, error) {
	if limit < 1 || limit > 1001 {
		return nil, fmt.Errorf("agent limit must be 1–1001")
	}
	if after != "" && !ingest.Identifier(after) {
		return nil, fmt.Errorf("invalid agent cursor")
	}
	filter := ""
	if len(sensorOnly) > 0 && sensorOnly[0] {
		filter = " AND json_type(h.payload,'$.sensor')='object'"
	}
	rows, err := q.QueryContext(ctx, `SELECT a.id,a.asset_id,a.created_at,a.revoked,s.last_seen_at,s.last_report_at,s.latest_inventory_at,s.latest_inventory_id,h.received_at,h.payload,assets.name,assets.ip
 FROM agents a JOIN assets ON assets.id=a.asset_id LEFT JOIN agent_status s ON s.agent_id=a.id LEFT JOIN agent_heartbeats h ON h.agent_id=a.id
 WHERE a.id>? AND (?='' OR a.asset_id=?) `+filter+` ORDER BY a.id LIMIT ?`, after, asset, asset, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []ingest.AgentStatus{}
	for rows.Next() {
		var v ingest.AgentStatus
		var created string
		var seen, report, inventoryAt, inventoryID, heartbeat, payload sql.NullString
		if err = rows.Scan(&v.AgentID, &v.AssetID, &created, &v.Revoked, &seen, &report, &inventoryAt, &inventoryID, &heartbeat, &payload, &v.AssetName, &v.AssetIP); err != nil {
			return nil, err
		}
		if v.CreatedAt, err = parse(created); err != nil {
			return nil, err
		}
		for _, field := range []struct {
			src sql.NullString
			dst **time.Time
		}{{seen, &v.LastSeenAt}, {report, &v.LastReportAt}, {inventoryAt, &v.LatestInventoryAt}, {heartbeat, &v.LastHeartbeatAt}} {
			if field.src.Valid {
				at, e := parse(field.src.String)
				if e != nil {
					return nil, e
				}
				*field.dst = &at
			}
		}
		v.LatestInventoryID = inventoryID.String
		if payload.Valid {
			v.Health = &ingest.Heartbeat{}
			if err = json.Unmarshal([]byte(payload.String), v.Health); err != nil {
				return nil, err
			}
		}
		result = append(result, v)
	}
	return result, rows.Err()
}
func (s *Store) AgentQueueUsage(ctx context.Context, id string) (count, size int64, err error) {
	err = s.db.QueryRowContext(ctx, "SELECT count(*),COALESCE(sum(length(CAST(payload AS BLOB))),0) FROM agent_queue WHERE agent_id=?", id).Scan(&count, &size)
	return
}
