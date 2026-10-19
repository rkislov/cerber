// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/event"
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/ports"
)

var _ ports.InventoryStore = (*Store)(nil)

func (s *Store) SaveInventory(ctx context.Context, snapshot inventory.Snapshot, e event.Envelope) error {
	if err := snapshot.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	if int64(len(data)) > inventory.MaxSnapshotBytes {
		return fmt.Errorf("inventory exceeds 32 MiB")
	}
	return s.mutate(ctx, e, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO inventories(id,asset_id,collected_at,payload) VALUES(?,?,?,?)", snapshot.ID, snapshot.AssetID, stamp(snapshot.CollectedAt), string(data))
		return err
	})
}
func (s *Store) Inventory(ctx context.Context, id string) (inventory.Snapshot, error) {
	var data string
	var v inventory.Snapshot
	err := s.db.QueryRowContext(ctx, "SELECT payload FROM inventories WHERE id=?", id).Scan(&data)
	if err == sql.ErrNoRows {
		return v, domain.ErrNotFound
	}
	if err != nil {
		return v, err
	}
	err = json.Unmarshal([]byte(data), &v)
	return v, err
}
func (s *Store) Inventories(ctx context.Context, asset string, limit int) ([]inventory.Summary, error) {
	if limit < 1 || limit > 100 {
		return nil, fmt.Errorf("inventory limit must be 1–100")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,asset_id,collected_at,json_extract(payload,'$.collector'),json_extract(payload,'$.os'),json_extract(payload,'$.coverage'),json_array_length(payload,'$.components'),json_array_length(payload,'$.updates') FROM inventories WHERE asset_id=? ORDER BY collected_at DESC,sequence DESC LIMIT ?`, asset, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []inventory.Summary{}
	for rows.Next() {
		var v inventory.Summary
		var at, osData, coverage string
		var components, updates sql.NullInt64
		if err = rows.Scan(&v.ID, &v.AssetID, &at, &v.Collector, &osData, &coverage, &components, &updates); err != nil {
			return nil, err
		}
		if v.CollectedAt, err = parse(at); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(osData), &v.OS); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(coverage), &v.Coverage); err != nil {
			return nil, err
		}
		v.ComponentCount = int(components.Int64)
		v.UpdateCount = int(updates.Int64)
		result = append(result, v)
	}
	return result, rows.Err()
}
func (s *Store) SaveUpdateCheck(ctx context.Context, check inventory.Check, e event.Envelope) error {
	if err := check.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(check)
	if err != nil {
		return err
	}
	return s.mutate(ctx, e, func(tx *sql.Tx) error {
		var asset string
		if err := tx.QueryRowContext(ctx, "SELECT asset_id FROM inventories WHERE id=?", check.InventoryID).Scan(&asset); err != nil {
			return err
		}
		if asset != check.AssetID {
			return fmt.Errorf("update check inventory belongs to a different asset")
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO update_checks(id,asset_id,inventory_id,checked_at,payload) VALUES(?,?,?,?,?)", check.ID, check.AssetID, check.InventoryID, stamp(check.CheckedAt), string(data))
		return err
	})
}
func (s *Store) UpdateChecks(ctx context.Context, asset string, limit int) ([]inventory.Check, error) {
	if limit < 1 || limit > 100 {
		return nil, fmt.Errorf("update check limit must be 1–100")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT payload FROM update_checks WHERE asset_id=? ORDER BY checked_at DESC,sequence DESC LIMIT ?", asset, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []inventory.Check{}
	for rows.Next() {
		var data string
		var v inventory.Check
		if err = rows.Scan(&data); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(data), &v); err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	return result, rows.Err()
}
