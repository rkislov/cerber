// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/rkislov/cerber/internal/telemetry"
	"strings"
	"time"
)

func networkContext(ctx context.Context, tx *sql.Tx, c *telemetry.EventChain, allow func(telemetry.Normalized) (bool, error)) error {
	steps := append([]telemetry.ChainStep{}, c.Steps...)
	seen := map[string]bool{}
	for _, a := range steps {
		seen[a.EventID] = true
	}
	for _, a := range steps {
		p := a.WindowsActivity
		if a.Code != "4688" || p == nil || telemetry.WindowsPID(p.ProcessID) == "" || p.Process == "" {
			continue
		}
		if p.TargetSID != "" && p.TargetSID != "S-1-0-0" && p.TargetSID != a.Identity.AccountSID {
			continue
		}
		ok, e := allow(telemetry.Normalized{AgentID: a.AgentID, User: a.User, SourceIP: a.SourceIP})
		if e != nil {
			return e
		}
		if !ok {
			continue
		}
		rows, e := tx.QueryContext(ctx, `SELECT payload FROM normalized_events WHERE agent_id=? AND status='parsed' AND event_time>? AND event_time<=? AND class IN ('process','network_connection') ORDER BY event_time,sequence LIMIT 201`, a.AgentID, stamp(a.At), stamp(a.At.Add(30*time.Minute)))
		if e != nil {
			return e
		}
		values := []telemetry.Normalized{}
		size := 0
		for rows.Next() {
			var b string
			if e = rows.Scan(&b); e != nil {
				break
			}
			size += len(b)
			if size > 1<<20 {
				c.Truncated = true
				break
			}
			var n telemetry.Normalized
			if e = json.Unmarshal([]byte(b), &n); e != nil {
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
		if len(values) > 200 {
			c.Truncated = true
			values = values[:200]
		}
		for _, n := range values {
			w := n.WindowsActivity
			if n.AssetID != a.AssetID || w == nil || telemetry.WindowsPID(w.ProcessID) != telemetry.WindowsPID(p.ProcessID) {
				continue
			}
			if n.Action == "process_created" || n.Action == "process_exited" {
				break
			}
			if n.Code != "5156" || seen[n.ID] || !strings.EqualFold(w.Process, p.Process) {
				continue
			}
			closed, e := sessionBoundary(ctx, tx, a, n.EventTime)
			if e != nil {
				return e
			}
			if closed {
				break
			}
			ok, e := allow(n)
			if e != nil {
				return e
			}
			if !ok {
				continue
			}
			if len(c.Steps) >= 20 {
				c.Truncated = true
				return nil
			}
			seen[n.ID] = true
			c.Steps = append(c.Steps, telemetry.ChainStep{EventID: n.ID, AgentID: n.AgentID, AssetID: n.AssetID, At: n.EventTime, Code: n.Code, Action: n.Action, Outcome: n.Outcome, SourceIP: n.SourceIP, Identity: *n.Identity, WindowsActivity: w})
			c.Links = append(c.Links, telemetry.ChainLink{From: a.EventID, To: n.ID, Kind: "process_connection", Basis: "Тот же узел, PID и точный путь приложения; после 4688, до наблюдаемого завершения/повторного использования PID или границы сеанса. 5156 означает разрешение WFP, не подтверждение передачи данных. Учётка создателя процесса не приписывается сетевому событию."})
		}
	}
	for _, a := range c.Steps {
		for _, b := range c.Steps {
			if networkTupleMatch(a, b) {
				c.Links = append(c.Links, telemetry.ChainLink{From: a.EventID, To: b.EventID, Kind: "network_tuple", Basis: "Сетевое сопоставление: исходящий и входящий 5156 на разных узлах, одинаковые TCP-адреса/порты, до 5 секунд. NAT, переиспользование портов и рассинхронизация часов ограничивают вывод; это не доказательство атаки или входа пользователя."})
			}
		}
	}
	return nil
}
func networkTupleMatch(a, b telemetry.ChainStep) bool {
	x, y := a.WindowsActivity, b.WindowsActivity
	if a.Code != "5156" || b.Code != "5156" || a.AgentID == b.AgentID || a.AssetID == b.AssetID || x == nil || y == nil {
		return false
	}
	d := b.At.Sub(a.At)
	return d >= -5*time.Second && d <= 5*time.Second && x.Direction == "%%14593" && y.Direction == "%%14592" && x.Protocol == "6" && y.Protocol == "6" && telemetry.RemoteAddress(x.SourceAddress) && telemetry.RemoteAddress(x.DestinationAddress) && x.SourcePort != "" && x.DestinationPort != "" && x.SourceAddress == y.SourceAddress && x.DestinationAddress == y.DestinationAddress && x.SourcePort == y.SourcePort && x.DestinationPort == y.DestinationPort
}
