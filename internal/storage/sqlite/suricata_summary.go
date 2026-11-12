// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"encoding/json"
	rules "github.com/rkislov/cerber/internal/suricatarules"
	"time"
)

func (s *Store) SuricataSummary(ctx context.Context, now time.Time) (rules.Summary, error) {
	v := rules.Summary{AsOf: now, Applied: []rules.AppliedSummary{}}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT manifest FROM suricata_bundles ORDER BY json_extract(manifest,'$.created_at') DESC,id`)
	if err != nil {
		return v, err
	}
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return v, err
		}
		var m rules.Manifest
		if err = json.Unmarshal([]byte(raw), &m); err != nil {
			rows.Close()
			return v, err
		}
		if v.Latest == nil && (m.Source == "feed" || m.Source == "et-open") {
			v.Latest = &m
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return v, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT b.id,json_extract(b.manifest,'$.count'),json_extract(b.manifest,'$.engine_major'),count(*),sum(CASE WHEN h.received_at>=? AND h.received_at<=? AND json_extract(h.payload,'$.sensor.suricata.state')='applied' THEN 1 ELSE 0 END)
FROM agents a JOIN agent_heartbeats h ON h.agent_id=a.id JOIN suricata_bundles b ON b.id=json_extract(h.payload,'$.sensor.suricata.applied_id')
WHERE a.revoked=0 GROUP BY b.id ORDER BY b.id`, stamp(now.Add(-3*time.Minute)), stamp(now))
	if err != nil {
		return v, err
	}
	for rows.Next() {
		var a rules.AppliedSummary
		if err = rows.Scan(&a.ID, &a.Count, &a.EngineMajor, &a.Sensors, &a.FreshSensors); err != nil {
			rows.Close()
			return v, err
		}
		v.Applied = append(v.Applied, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return v, err
	}
	err = tx.QueryRowContext(ctx, `SELECT count(*) FROM agents a JOIN suricata_assignments s ON s.agent_id=a.id LEFT JOIN agent_heartbeats h ON h.agent_id=a.id WHERE a.revoked=0 AND json_extract(s.payload,'$.bundle.id') IS NOT NULL AND (coalesce(json_extract(h.payload,'$.sensor.suricata.applied_id'),'')!=json_extract(s.payload,'$.bundle.id') OR coalesce(json_extract(h.payload,'$.sensor.suricata.state'),'')!='applied')`).Scan(&v.PendingSensors)
	return v, err
}
