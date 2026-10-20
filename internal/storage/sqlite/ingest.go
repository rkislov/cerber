// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/event"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/inventory"
	"time"
)

var ErrUnauthorized = ingest.ErrUnauthorized

func (s *Store) RegisterAgent(ctx context.Context, id, asset, hash string) error {
	if !ingest.Identifier(id) || len(hash) != 64 {
		return fmt.Errorf("invalid agent identity")
	}
	e, err := event.New("agent.enrolled", asset, map[string]string{"agent_id": id, "asset_id": asset})
	if err != nil {
		return err
	}
	return s.mutate(ctx, e, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO agents(id,asset_id,token_hash,created_at) VALUES(?,?,?,?)", id, asset, hash, stamp(time.Now()))
		return err
	})
}
func (s *Store) RevokeAgent(ctx context.Context, id string) error {
	e, err := event.New("agent.revoked", id, map[string]string{"agent_id": id})
	if err != nil {
		return err
	}
	return s.mutate(ctx, e, func(tx *sql.Tx) error {
		r, err := tx.ExecContext(ctx, "UPDATE agents SET revoked=1 WHERE id=? AND revoked=0", id)
		if err != nil {
			return err
		}
		n, _ := r.RowsAffected()
		if n == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func agentBinding(ctx context.Context, q rowQuerier, id, hash string) (string, error) {
	var asset, stored string
	var revoked int
	err := q.QueryRowContext(ctx, "SELECT asset_id,token_hash,revoked FROM agents WHERE id=?", id).Scan(&asset, &stored, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrUnauthorized
	}
	if err != nil {
		return "", err
	}
	if revoked != 0 || subtle.ConstantTimeCompare([]byte(stored), []byte(hash)) != 1 {
		return "", ErrUnauthorized
	}
	return asset, nil
}
func (s *Store) AgentBinding(ctx context.Context, id, hash string) (string, error) {
	return agentBinding(ctx, s.db, id, hash)
}

// AcceptReport commits the inventory, checks, receipt and events together. IDs are
// namespaced by authenticated agent; payload asset IDs never control server ownership.
func (s *Store) AcceptReport(ctx context.Context, id, hash string, r ingest.Report) (ingest.Receipt, error) {
	var receipt ingest.Receipt
	if r.AgentID != id {
		return receipt, ErrUnauthorized
	}
	if err := r.Validate(); err != nil {
		return receipt, err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return receipt, err
	}
	if int64(len(data)) > ingest.MaxReportBytes {
		return receipt, fmt.Errorf("report too large")
	}
	digest := ingest.Hash(data)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return receipt, err
	}
	defer tx.Rollback()
	asset, err := agentBinding(ctx, tx, id, hash)
	if err != nil {
		return receipt, err
	}
	var priorDigest, priorReceipt string
	err = tx.QueryRowContext(ctx, "SELECT digest,receipt FROM agent_receipts WHERE agent_id=? AND report_id=?", id, r.ID).Scan(&priorDigest, &priorReceipt)
	if err == nil {
		if priorDigest != digest {
			return receipt, domain.ErrConflict
		}
		if err = json.Unmarshal([]byte(priorReceipt), &receipt); err != nil {
			return receipt, err
		}
		receipt.Duplicate = true
		if err = recordReportContact(ctx, tx, id, receipt.SnapshotID, r.Snapshot.CollectedAt, time.Now().UTC()); err != nil {
			return receipt, err
		}
		return receipt, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return receipt, err
	}
	snap := r.Snapshot
	snap.AssetID = asset
	snap.ID = ingest.RemoteID(id, "inventory", snap.ID)
	insert := func(table, key, payload string, fn func() error) (bool, error) {
		var previous string
		err := tx.QueryRowContext(ctx, "SELECT payload FROM "+table+" WHERE id=?", key).Scan(&previous)
		if err == nil {
			if previous != payload {
				return false, domain.ErrConflict
			}
			return false, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
		return true, fn()
	}
	emit := func(kind string, payload any) error {
		e, err := event.New(kind, asset, payload)
		if err != nil {
			return err
		}
		e.Source = "agent:" + id
		return appendEvent(ctx, tx, e)
	}
	payload, _ := json.Marshal(snap)
	added, err := insert("inventories", snap.ID, string(payload), func() error {
		_, e := tx.ExecContext(ctx, "INSERT INTO inventories(id,asset_id,collected_at,payload) VALUES(?,?,?,?)", snap.ID, asset, stamp(snap.CollectedAt), string(payload))
		return e
	})
	if err != nil {
		return receipt, err
	}
	if added {
		if err = emit("inventory.recorded", map[string]any{"asset_id": asset, "snapshot_id": snap.ID, "agent_id": id, "collected_at": snap.CollectedAt, "coverage": snap.Coverage, "components": len(snap.Components), "updates": len(snap.Updates)}); err != nil {
			return receipt, err
		}
	}
	for _, c := range r.Checks {
		c.AssetID = asset
		c.InventoryID = snap.ID
		c.ID = ingest.RemoteID(id, "check", c.ID)
		payload, _ := json.Marshal(c)
		added, err = insert("update_checks", c.ID, string(payload), func() error {
			_, e := tx.ExecContext(ctx, "INSERT INTO update_checks(id,asset_id,inventory_id,checked_at,payload) VALUES(?,?,?,?,?)", c.ID, asset, c.InventoryID, stamp(c.CheckedAt), string(payload))
			return e
		})
		if err != nil {
			return receipt, err
		}
		if added {
			if err = emit("updates.checked", c); err != nil {
				return receipt, err
			}
		}
	}
	receipt = ingest.Receipt{AgentID: id, ReportID: r.ID, SnapshotID: snap.ID, ReceivedAt: time.Now().UTC()}
	payload, _ = json.Marshal(receipt)
	if _, err = tx.ExecContext(ctx, "INSERT INTO agent_receipts(agent_id,report_id,digest,receipt) VALUES(?,?,?,?)", id, r.ID, digest, string(payload)); err != nil {
		return receipt, err
	}
	if err = emit("agent.report_received", receipt); err != nil {
		return receipt, err
	}
	if err = recordReportContact(ctx, tx, id, snap.ID, snap.CollectedAt, receipt.ReceivedAt); err != nil {
		return receipt, err
	}
	return receipt, tx.Commit()
}

// QueueInventory captures the current immutable snapshot and all its checks in one
// transaction. Queue limits bound offline disk consumption; nothing is evicted silently.
func (s *Store) QueueInventory(ctx context.Context, agent, snapshotID string) (ingest.Report, error) {
	r := ingest.Report{SchemaVersion: 1, AgentID: agent, Checks: []inventory.Check{}}
	id, err := domain.NewID()
	if err != nil {
		return r, err
	}
	r.ID = id
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer tx.Rollback()
	var payload string
	if err = tx.QueryRowContext(ctx, "SELECT payload FROM inventories WHERE id=?", snapshotID).Scan(&payload); err != nil {
		return r, err
	}
	if err = json.Unmarshal([]byte(payload), &r.Snapshot); err != nil {
		return r, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT payload FROM update_checks WHERE inventory_id=? ORDER BY sequence LIMIT 101", snapshotID)
	if err != nil {
		return r, err
	}
	for rows.Next() {
		var p string
		var c inventory.Check
		if err = rows.Scan(&p); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(p), &c); err != nil {
			break
		}
		r.Checks = append(r.Checks, c)
	}
	rowErr := rows.Err()
	rows.Close()
	if err != nil {
		return r, err
	}
	if rowErr != nil {
		return r, rowErr
	}
	if err = r.Validate(); err != nil {
		return r, err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return r, err
	}
	if int64(len(data)) > ingest.MaxReportBytes {
		return r, fmt.Errorf("report too large")
	}
	var count, size int64
	if err = tx.QueryRowContext(ctx, "SELECT count(*),COALESCE(sum(length(CAST(payload AS BLOB))),0) FROM agent_queue").Scan(&count, &size); err != nil {
		return r, err
	}
	if count >= 100 || size+int64(len(data)) > 256<<20 {
		return r, fmt.Errorf("agent queue full (100 reports / 256 MiB); flush before collecting more")
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO agent_queue(agent_id,report_id,payload) VALUES(?,?,?)", agent, r.ID, string(data)); err != nil {
		return r, err
	}
	return r, tx.Commit()
}
func (s *Store) NextReport(ctx context.Context, agent string) (ingest.Report, error) {
	var data string
	var r ingest.Report
	err := s.db.QueryRowContext(ctx, "SELECT payload FROM agent_queue WHERE agent_id=? ORDER BY sequence LIMIT 1", agent).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return r, domain.ErrNotFound
	}
	if err != nil {
		return r, err
	}
	err = json.Unmarshal([]byte(data), &r)
	return r, err
}
func (s *Store) AckReport(ctx context.Context, agent, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM agent_queue WHERE agent_id=? AND report_id=?", agent, id)
	return err
}

func (s *Store) QueueUsage(ctx context.Context) (count, size int64, err error) {
	err = s.db.QueryRowContext(ctx, "SELECT count(*),COALESCE(sum(length(CAST(payload AS BLOB))),0) FROM agent_queue").Scan(&count, &size)
	return
}
