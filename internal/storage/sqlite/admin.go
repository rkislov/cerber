// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/domain"
	"net/netip"
	"time"
)

func (s *Store) AdminOverview(ctx context.Context, now time.Time, p alerts.Policy) (admin.Overview, error) {
	var v admin.Overview
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(NOT a.revoked AND s.last_seen_at>=?),0),COALESCE(SUM(NOT a.revoked AND s.last_seen_at<?),0),COALESCE(SUM(NOT a.revoked AND s.last_seen_at IS NULL),0),COALESCE(SUM(a.revoked),0),COALESCE(SUM(NOT a.revoked AND s.latest_inventory_id IS NOT NULL AND s.latest_inventory_at<?),0),COALESCE(SUM(NOT a.revoked AND s.latest_inventory_id IS NULL),0) FROM agents a LEFT JOIN agent_status s ON s.agent_id=a.id`, stamp(now.Add(-p.OfflineAfter)), stamp(now.Add(-p.OfflineAfter)), stamp(now.Add(-p.InventoryMaxAge))).Scan(&v.Agents, &v.Online, &v.Offline, &v.NeverSeen, &v.Revoked, &v.InventoryStale, &v.InventoryMissing)
	if err != nil {
		return v, err
	}
	err = s.db.QueryRowContext(ctx, "SELECT count(*),COALESCE(sum(acknowledged_at IS NULL),0) FROM alerts WHERE resolved_at IS NULL").Scan(&v.ActiveAlerts, &v.Unacknowledged)
	if err != nil {
		return v, err
	}
	rows, e := s.db.QueryContext(ctx, "SELECT DISTINCT x.ip FROM agents a JOIN assets x ON x.id=a.asset_id WHERE NOT a.revoked")
	if e != nil {
		return v, e
	}
	defer rows.Close()
	ips := map[string]bool{}
	networks := map[string]bool{}
	for rows.Next() {
		var value string
		if e = rows.Scan(&value); e != nil {
			return v, e
		}
		ip, e := netip.ParseAddr(value)
		if e != nil {
			continue
		}
		ip = ip.Unmap()
		ips[ip.String()] = true
		bits := 64
		if ip.Is4() {
			bits = 24
		}
		networks[netip.PrefixFrom(ip, bits).Masked().String()] = true
	}
	v.IPAddresses = len(ips)
	v.Subnets = len(networks)
	return v, rows.Err()
}
func (s *Store) AdminInventory(ctx context.Context, id, section string, offset, limit int) (admin.InventoryPage, error) {
	v := admin.InventoryPage{Section: section, Offset: offset, Items: []json.RawMessage{}}
	if section != "components" && section != "updates" && section != "updates_available" || offset < 0 || offset > 100000 || limit < 1 || limit > 100 {
		return v, fmt.Errorf("invalid inventory pagination")
	}
	var at, osData, coverage string
	var pm, metadata sql.NullString
	var components, updates sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id,asset_id,collected_at,json_extract(payload,'$.collector'),json_extract(payload,'$.os'),json_extract(payload,'$.coverage'),json_array_length(payload,'$.components'),json_array_length(payload,'$.updates'),json_extract(payload,'$.package_manager'),json_extract(payload,'$.repository_metadata') FROM inventories WHERE id=?`, id).Scan(&v.Summary.ID, &v.Summary.AssetID, &at, &v.Summary.Collector, &osData, &coverage, &components, &updates, &pm, &metadata)
	if errors.Is(err, sql.ErrNoRows) {
		return v, domain.ErrNotFound
	}
	if err != nil {
		return v, err
	}
	if v.Summary.CollectedAt, err = parse(at); err != nil {
		return v, err
	}
	if err = json.Unmarshal([]byte(osData), &v.Summary.OS); err != nil {
		return v, err
	}
	if err = json.Unmarshal([]byte(coverage), &v.Summary.Coverage); err != nil {
		return v, err
	}
	v.Summary.ComponentCount = int(components.Int64)
	v.Summary.UpdateCount = int(updates.Int64)
	v.PackageManager = pm.String
	v.RepositoryMetadata = metadata.String
	v.Total = v.Summary.ComponentCount
	if section == "updates" {
		v.Total = v.Summary.UpdateCount
	}
	array := section
	available := section == "updates_available"
	if available {
		array = "updates"
		if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM inventories i,json_each(i.payload,'$.updates') e WHERE i.id=? AND json_extract(e.value,'$.state')='available'`, id).Scan(&v.Total); err != nil {
			return v, err
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT e.value FROM inventories i,json_each(i.payload,?) e WHERE i.id=? AND e.value IS NOT NULL AND (?=0 OR json_extract(e.value,'$.state')='available') ORDER BY CAST(e.key AS INTEGER) LIMIT ? OFFSET ?`, "$."+array, id, available, limit, offset)
	if err != nil {
		return v, err
	}
	defer rows.Close()
	for rows.Next() {
		var value string
		if err = rows.Scan(&value); err != nil {
			return v, err
		}
		v.Items = append(v.Items, json.RawMessage(value))
	}
	return v, rows.Err()
}
