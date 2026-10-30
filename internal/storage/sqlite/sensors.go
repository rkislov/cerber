// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/event"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/sensorstate"
	"time"
)

func sensorPolicy(ctx context.Context, q rowQuerier, id string) (sensorstate.Policy, error) {
	var p sensorstate.Policy
	var data string
	e := q.QueryRowContext(ctx, "SELECT payload FROM sensor_policies WHERE agent_id=?", id).Scan(&data)
	if errors.Is(e, sql.ErrNoRows) {
		return p, nil
	}
	if e != nil {
		return p, e
	}
	e = json.Unmarshal([]byte(data), &p)
	return p, e
}
func (s *Store) SensorPolicy(ctx context.Context, id string) (sensorstate.Policy, error) {
	return sensorPolicy(ctx, s.db, id)
}
func (s *Store) SensorStatuses(ctx context.Context, after string, limit int) ([]ingest.AgentStatus, error) {
	return agentStatuses(ctx, s.db, "", after, limit, true)
}
func (s *Store) ChangeSensorPolicy(ctx context.Context, c sensorstate.Change) (sensorstate.Policy, error) {
	var p sensorstate.Policy
	if !ingest.Identifier(c.AgentID) || c.ExpectedRevision < 0 || sensorstate.ValidateControls(c.Inputs) != nil {
		return p, sensorstate.ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return p, e
	}
	defer tx.Rollback()
	u, ok := admin.Principal(ctx)
	if !ok || u.Username == "" || u.Role != "administrator" {
		return p, admin.ErrForbidden
	}
	if e = checkAdmin(ctx, tx, true); e != nil {
		return p, e
	}
	var payload string
	var revoked bool
	e = tx.QueryRowContext(ctx, `SELECT h.payload,a.revoked FROM agents a JOIN agent_heartbeats h ON h.agent_id=a.id WHERE a.id=?`, c.AgentID).Scan(&payload, &revoked)
	if errors.Is(e, sql.ErrNoRows) {
		return p, sensorstate.ErrNotFound
	}
	if e != nil {
		return p, e
	}
	if revoked {
		return p, sensorstate.ErrConflict
	}
	var h ingest.Heartbeat
	if json.Unmarshal([]byte(payload), &h) != nil || h.Sensor == nil {
		return p, sensorstate.ErrNotFound
	}
	if e = sensorstate.Match(c.Inputs, h.Sensor.Inputs); e != nil {
		return p, e
	}
	old, e := sensorPolicy(ctx, tx, c.AgentID)
	if e != nil {
		return p, e
	}
	if old.Revision != c.ExpectedRevision || old.Revision >= 1<<53-1 {
		return p, sensorstate.ErrConflict
	}
	p = sensorstate.Policy{Revision: old.Revision + 1, Inputs: c.Inputs, UpdatedAt: time.Now().UTC(), UpdatedBy: u.Username}
	data, e := json.Marshal(p)
	if e != nil {
		return p, e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO sensor_policies(agent_id,revision,payload) VALUES(?,?,?) ON CONFLICT(agent_id) DO UPDATE SET revision=excluded.revision,payload=excluded.payload`, c.AgentID, p.Revision, string(data))
	if e != nil {
		return p, e
	}
	ev, e := event.New("sensor.policy_changed", c.AgentID, map[string]any{"agent_id": c.AgentID, "actor": u.Username, "previous": old, "policy": p})
	if e != nil {
		return p, e
	}
	ev.Source = "admin:" + u.Username
	if e = appendEvent(ctx, tx, ev); e != nil {
		return p, e
	}
	return p, tx.Commit()
}
