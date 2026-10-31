// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/rkislov/cerber/internal/ingest"
	rules "github.com/rkislov/cerber/internal/suricatarules"
)

func matchingSuricataGroups(ctx context.Context, tx *sql.Tx, agent string, major int) ([]rules.GroupPolicy, error) {
	rows, e := tx.QueryContext(ctx, `SELECT r.payload FROM suricata_group_rules r JOIN agent_groups g ON g.id=r.group_id JOIN agent_group_members m ON m.group_id=g.id WHERE m.agent_id=? AND g.archived=0 AND json_extract(r.payload,'$.enabled')=1 AND json_extract(r.payload,'$.engine_major')=? ORDER BY r.group_id`, agent, major)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []rules.GroupPolicy{}
	for rows.Next() {
		var data string
		var p rules.GroupPolicy
		if e = rows.Scan(&data); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(data), &p); e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Called in the authenticated heartbeat transaction after storing the incoming
// status. Membership is evaluated afresh; overlapping policies never race to win.
func reconcileSuricataGroup(ctx context.Context, tx *sql.Tx, id string, h ingest.Heartbeat) error {
	if h.Sensor == nil || h.Sensor.Rules == nil {
		return nil
	}
	status := h.Sensor.Rules
	held, e := rolloutAgentHeld(ctx, tx, id)
	if e != nil || held {
		return e
	}
	groups, e := matchingSuricataGroups(ctx, tx, id, status.EngineMajor)
	if e != nil {
		return e
	}
	old, e := suricataAssignment(ctx, tx, id)
	if e != nil {
		return e
	}
	if len(groups) == 0 {
		if old.GroupID != "" {
			old.GroupID = ""
			old.GroupRevision = 0
			p, _ := json.Marshal(old)
			_, e = tx.ExecContext(ctx, "UPDATE suricata_assignments SET payload=? WHERE agent_id=?", string(p), id)
		}
		return e
	}
	if len(groups) > 1 || status.State == "unconfigured" {
		return nil
	}
	p := groups[0]
	if p.State != "ready" || p.ActiveID == "" {
		return nil
	}
	if old.Bundle.ID == p.ActiveID {
		if old.GroupID == p.GroupID {
			// A failed attempt is retried only after an explicit policy revision,
			// never on every heartbeat. An unresolved rollback still needs local recovery.
			if status.State != "error" || status.Revision != old.Revision || p.Revision <= old.GroupRevision {
				return nil
			}
		} else if status.State == "applied" && status.Revision == old.Revision && status.AppliedID == p.ActiveID {
			// Taking ownership of the already confirmed rules does not require
			// another engine reload (which temporarily needs a second ruleset in RAM).
			old.GroupID = p.GroupID
			old.GroupRevision = p.Revision
			data, err := json.Marshal(old)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, "UPDATE suricata_assignments SET payload=? WHERE agent_id=?", string(data), id)
			return err
		}
	}
	_, e = assignSuricata(ctx, tx, rules.Change{AgentID: id, ExpectedRevision: old.Revision, BundleID: p.ActiveID}, "system:suricata-group", p.GroupID, p.Revision)
	return e
}
func (s *Store) SuricataGroups(ctx context.Context) ([]rules.GroupView, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	rows, e := tx.QueryContext(ctx, "SELECT r.payload,g.name,g.archived FROM suricata_group_rules r JOIN agent_groups g ON g.id=r.group_id ORDER BY g.name LIMIT 32")
	if e != nil {
		return nil, e
	}
	out := []rules.GroupView{}
	for rows.Next() {
		var v rules.GroupView
		var p string
		if e = rows.Scan(&p, &v.Name, &v.Archived); e != nil {
			rows.Close()
			return nil, e
		}
		if e = json.Unmarshal([]byte(p), &v.Policy); e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	now := time.Now().UTC()
	for i := range out {
		v := &out[i]
		v.Rollout, e = readSuricataRollout(ctx, tx, v.Policy.GroupID)
		if e != nil {
			return nil, e
		}
		v.Members = []rules.GroupMember{}
		rows, e = tx.QueryContext(ctx, `SELECT a.id,s.name,a.revoked,coalesce(h.received_at,''),coalesce(h.payload,''),coalesce(r.payload,'') FROM agent_group_members m JOIN agents a ON a.id=m.agent_id JOIN assets s ON s.id=a.asset_id LEFT JOIN agent_heartbeats h ON h.agent_id=a.id LEFT JOIN suricata_assignments r ON r.agent_id=a.id WHERE m.group_id=? ORDER BY a.id LIMIT 500`, v.Policy.GroupID)
		if e != nil {
			return nil, e
		}
		type member struct {
			v                     rules.GroupMember
			revoked               bool
			heartbeat, assignment string
		}
		var members []member
		for rows.Next() {
			var m member
			var received string
			if e = rows.Scan(&m.v.AgentID, &m.v.Name, &m.revoked, &received, &m.heartbeat, &m.assignment); e != nil {
				rows.Close()
				return nil, e
			}
			m.v.LastHeartbeat, _ = parse(received)
			members = append(members, m)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
		for _, m := range members {
			h := ingest.Heartbeat{}
			a := rules.Assignment{}
			_ = json.Unmarshal([]byte(m.heartbeat), &h)
			_ = json.Unmarshal([]byte(m.assignment), &a)
			st := rules.Status{}
			configured := h.Sensor != nil && h.Sensor.Rules != nil
			if configured {
				st = *h.Sensor.Rules
			}
			m.v.AppliedID = st.AppliedID
			m.v.DesiredID = v.Policy.ActiveID
			m.v.Error = st.Error
			owners, e := matchingSuricataGroups(ctx, tx, m.v.AgentID, v.Policy.EngineMajor)
			if e != nil {
				return nil, e
			}
			switch {
			case m.revoked:
				m.v.State = "revoked"
			case !configured || st.State == "unconfigured":
				m.v.State = "unconfigured"
			case st.EngineMajor != v.Policy.EngineMajor:
				m.v.State = "incompatible"
			case !v.Policy.Enabled || v.Archived:
				m.v.State = "disabled"
			case len(owners) > 1:
				m.v.State = "conflict"
			case now.Sub(m.v.LastHeartbeat) > 5*time.Minute:
				m.v.State = "offline"
			case v.Policy.State != "ready":
				m.v.State = v.Policy.State
				m.v.Error = v.Policy.Error
			case a.GroupID != v.Policy.GroupID || a.Bundle.ID != v.Policy.ActiveID || st.Revision < a.Revision:
				m.v.State = "pending"
			default:
				m.v.State = st.State
			}
			if v.Rollout != nil && v.Policy.State != "ready" {
				for _, rm := range v.Rollout.Members {
					if rm.AgentID == m.v.AgentID {
						m.v.State, m.v.Error = rm.State, rm.Error
						m.v.DesiredID = v.Rollout.CandidateID
						if rm.State == "unchanged" || rm.State == "rolled_back" || rm.State == "rollback_pending" || rm.State == "rollback_failed" {
							m.v.DesiredID = rm.PreviousID
						}
					}
				}
			}
			v.Members = append(v.Members, m.v)
		}
	}
	return out, nil
}
