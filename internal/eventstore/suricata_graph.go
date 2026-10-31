// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/rkislov/cerber/internal/telemetry"
	"time"
)

func sameSuricataFlow(a telemetry.ChainStep, n telemetry.Normalized) bool {
	x, y := a.Network, n.Network
	if x == nil || y == nil || x.FlowID == "" || x.FlowID == "0" || x.FlowID != y.FlowID || a.AgentID != n.AgentID || a.AssetID != n.AssetID || x.Input != y.Input || x.Exporter != y.Exporter || x.Transport != y.Transport || x.CaptureInterface != y.CaptureInterface || x.Protocol == 0 || x.Protocol != y.Protocol || n.Status != "parsed" || y.Kind != "suricata.flow" {
		return false
	}
	direct := a.SourceIP == n.SourceIP && a.DestinationIP == n.DestinationIP && x.SourcePort == y.SourcePort && a.DestinationPort == n.DestinationPort
	reverse := a.SourceIP == n.DestinationIP && a.DestinationIP == n.SourceIP && x.SourcePort == n.DestinationPort && a.DestinationPort == y.SourcePort
	if !direct && !reverse || y.Start == nil || y.End == nil {
		return false
	}
	return !a.At.Before(y.Start.Add(-time.Second)) && !a.At.After(y.End.Add(time.Second))
}

// Flow IDs alone are not global identities. Require the same observer, input,
// interface, bidirectional tuple and a flow interval containing the alert.
func suricataContext(ctx context.Context, tx *sql.Tx, c *telemetry.EventChain, allow func(telemetry.Normalized) (bool, error)) error {
	original := append([]telemetry.ChainStep(nil), c.Steps...)
	seen := map[string]bool{}
	for _, a := range original {
		seen[a.EventID] = true
	}
	for _, a := range original {
		if a.Network == nil || a.Network.Kind != "suricata.alert" || a.Network.FlowID == "" {
			continue
		}
		ok, e := allow(telemetry.Normalized{AgentID: a.AgentID, SourceIP: a.SourceIP, DestinationIP: a.DestinationIP})
		if e != nil {
			return e
		}
		if !ok {
			continue
		}
		rows, e := tx.QueryContext(ctx, `SELECT payload FROM normalized_events WHERE class IN ('network_flow','network_alert') AND status='parsed' AND source_ip IN (?,?) AND event_time>=? AND event_time<=? AND agent_id=? ORDER BY event_time,sequence LIMIT 101`, a.SourceIP, a.DestinationIP, stamp(a.At.Add(-time.Second)), stamp(a.At.Add(30*time.Minute)), a.AgentID)
		if e != nil {
			return e
		}
		values := []telemetry.Normalized{}
		size := 0
		for rows.Next() {
			var p string
			if e = rows.Scan(&p); e != nil {
				break
			}
			size += len(p)
			if size > 512<<10 {
				c.Truncated = true
				break
			}
			var n telemetry.Normalized
			if e = json.Unmarshal([]byte(p), &n); e != nil {
				break
			}
			values = append(values, n)
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return e
		}
		if len(values) > 100 {
			values = values[:100]
			c.Truncated = true
		}
		for _, n := range values {
			if !sameSuricataFlow(a, n) {
				continue
			}
			ok, e := allow(n)
			if e != nil {
				return e
			}
			if !ok {
				continue
			}
			if !seen[n.ID] {
				if len(c.Steps) >= 20 {
					c.Truncated = true
					return nil
				}
				seen[n.ID] = true
				c.Steps = append(c.Steps, telemetry.ChainStep{EventID: n.ID, AgentID: n.AgentID, AssetID: n.AssetID, At: n.EventTime, Action: n.Action, Code: n.Code, Outcome: n.Outcome, SourceIP: n.SourceIP, DestinationIP: n.DestinationIP, DestinationPort: n.DestinationPort, Network: n.Network})
			}
			if len(c.Links) >= 200 {
				c.Truncated = true
				return nil
			}
			c.Links = append(c.Links, telemetry.ChainLink{From: a.EventID, To: n.ID, Kind: "suricata_flow", Basis: "Один сенсор, вход и интерфейс; совпали flow_id и двунаправленный сетевой кортеж. Время срабатывания входит в интервал EVE flow с допуском 1 секунда. Связь не устанавливает пользователя, владельца IP или успешность атаки."})
		}
	}
	return nil
}
