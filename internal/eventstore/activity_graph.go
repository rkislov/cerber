// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/rkislov/cerber/internal/telemetry"
	"time"
)

// Activity context is read at graph-open time; it never rewrites detections.
// Only a bounded same-host SID + local-session association is permitted.
func activityContext(ctx context.Context, tx *sql.Tx, c *telemetry.EventChain) (bool, error) {
	anchors := append([]telemetry.ChainStep{}, c.Steps...)
	seen := map[string]bool{}
	for _, v := range anchors {
		seen[v.EventID] = true
	}
	size := 0
	for _, a := range anchors {
		if a.Action != "logon" || a.Identity.AccountKey == "" || a.Identity.LocalSession == "" {
			continue
		}
		rows, e := tx.QueryContext(ctx, `SELECT payload FROM normalized_events INDEXED BY normalized_actor_session WHERE agent_id=? AND json_extract(payload,'$.identity.local_session') IS NOT NULL AND json_extract(payload,'$.identity.local_session')=? AND event_time>? AND event_time<=? AND class IN ('process','service','task') AND status='parsed' ORDER BY event_time,sequence LIMIT 21`, a.AgentID, a.Identity.LocalSession, stamp(a.At), stamp(a.At.Add(30*time.Minute)))
		if e != nil {
			return false, e
		}
		values := []telemetry.Normalized{}
		for rows.Next() {
			var p string
			if e = rows.Scan(&p); e != nil {
				break
			}
			size += len(p)
			if size > 1<<20 {
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
			return false, e
		}
		for _, n := range values {
			if len(c.Steps) >= 20 || size > 1<<20 {
				return true, nil
			}
			if seen[n.ID] || n.Identity == nil || n.AssetID != a.AssetID || n.Identity.AccountKey != a.Identity.AccountKey || !n.EventTime.After(a.At) {
				continue
			}
			seen[n.ID] = true
			c.Steps = append(c.Steps, telemetry.ChainStep{EventID: n.ID, AgentID: n.AgentID, AssetID: n.AssetID, At: n.EventTime, User: n.User, Action: n.Action, Code: n.Code, Outcome: n.Outcome, Identity: *n.Identity, WindowsActivity: n.WindowsActivity})
			c.Links = append(c.Links, telemetry.ChainLink{From: a.EventID, To: n.ID, Kind: "session_activity", Basis: "Контекст при открытии графа: тот же агент/актив, SID инициатора и локальный LogonId; после входа, не более 30 минут. Локальный ID может повторяться после перезагрузки. Это не самостоятельное доказательство атаки."})
		}
	}
	return false, nil
}

func serviceConfirmations(ctx context.Context, tx *sql.Tx, c *telemetry.EventChain) error {
	steps := append([]telemetry.ChainStep{}, c.Steps...)
	seen := map[string]bool{}
	for _, v := range steps {
		seen[v.EventID] = true
	}
	for _, a := range steps {
		w := a.WindowsActivity
		if a.Code != "4697" || w == nil || w.Name == "" || w.Image == "" {
			continue
		}
		rows, e := tx.QueryContext(ctx, `SELECT payload FROM normalized_events WHERE agent_id=? AND event_time>=? AND event_time<=? AND class='service' AND status='parsed' ORDER BY sequence LIMIT 21`, a.AgentID, stamp(a.At.Add(-5*time.Second)), stamp(a.At.Add(5*time.Second)))
		if e != nil {
			return e
		}
		values := []telemetry.Normalized{}
		for rows.Next() {
			var p string
			if e = rows.Scan(&p); e != nil {
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
		for _, n := range values {
			if len(c.Steps) >= 20 {
				c.Truncated = true
				return nil
			}
			v := n.WindowsActivity
			if seen[n.ID] || n.Code != "7045" || n.AssetID != a.AssetID || v == nil || v.Name != w.Name || v.Image != w.Image {
				continue
			}
			seen[n.ID] = true
			c.Steps = append(c.Steps, telemetry.ChainStep{EventID: n.ID, AgentID: n.AgentID, AssetID: n.AssetID, At: n.EventTime, Code: n.Code, Action: n.Action, Outcome: n.Outcome, Identity: *n.Identity, WindowsActivity: v})
			c.Links = append(c.Links, telemetry.ChainLink{From: a.EventID, To: n.ID, Kind: "service_confirmation", Basis: "Сопоставление записей установки: тот же узел, точные имя и путь службы, расхождение до 5 секунд. У 7045 нет подтверждённого инициатора или сеанса; эта связь не доказывает личность установившего службу."})
		}
	}
	return nil
}
