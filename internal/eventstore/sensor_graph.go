// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/rkislov/cerber/internal/telemetry"
	"strconv"
	"time"
)

func (s *Store) ensureNetworkIndexes(ctx context.Context) error {
	var present int
	if e := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name IN ('normalized_class_sequence','normalized_sensor_tuple','normalized_quarantine_sequence') AND type='index'`).Scan(&present); e != nil {
		return e
	}
	if present == 3 {
		return nil
	}
	if s.path != ":memory:" {
		var count int64
		if e := s.db.QueryRowContext(ctx, "SELECT count(*) FROM normalized_events").Scan(&count); e != nil {
			return e
		}
		p, e := retentionPolicy(ctx, s.db)
		if e != nil {
			return e
		}
		if e = s.checkWrite(ctx, s.db, p, count*192+(64<<20), true); e != nil {
			return e
		}
	}
	_, e := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS normalized_class_sequence ON normalized_events(class,sequence);
CREATE INDEX IF NOT EXISTS normalized_quarantine_sequence ON normalized_events(sequence) WHERE status='quarantine';
CREATE INDEX IF NOT EXISTS normalized_sensor_tuple ON normalized_events(source_ip,event_time,sequence) WHERE class IN ('network_flow','network_alert') AND status='parsed';`)
	return e
}

func sensorMatches(a telemetry.ChainStep, n telemetry.Normalized) bool {
	w, o := a.WindowsActivity, n.Network
	if a.Code != "5156" || w == nil || o == nil || n.Status != "parsed" || o.Protocol != 6 || w.Protocol != "6" || !telemetry.RemoteAddress(w.SourceAddress) || !telemetry.RemoteAddress(w.DestinationAddress) {
		return false
	}
	if (o.Kind == "netflow9" || o.Kind == "ipfix") && (o.Start == nil || o.End == nil) {
		return false
	}
	sp, e1 := strconv.Atoi(w.SourcePort)
	dp, e2 := strconv.Atoi(w.DestinationPort)
	if e1 != nil || e2 != nil || sp == 0 || dp == 0 || w.SourceAddress != n.SourceIP || w.DestinationAddress != n.DestinationIP || sp != o.SourcePort || dp != n.DestinationPort {
		return false
	}
	start, end := n.EventTime, n.EventTime
	if o.Start != nil && o.End != nil {
		start, end = *o.Start, *o.End
	}
	return !end.Before(start) && !a.At.Before(start.Add(-5*time.Second)) && !a.At.After(end.Add(5*time.Second))
}

// sensorContext adds independent observations, not target hosts inferred from IP.
// No account, local session or process identity is assigned to the sensor event.
func sensorContext(ctx context.Context, tx *sql.Tx, c *telemetry.EventChain, allow func(telemetry.Normalized) (bool, error)) error {
	steps := append([]telemetry.ChainStep{}, c.Steps...)
	seen := map[string]bool{}
	for _, a := range steps {
		seen[a.EventID] = true
	}
	for _, a := range steps {
		w := a.WindowsActivity
		if a.Code != "5156" || w == nil || w.Protocol != "6" || !telemetry.RemoteAddress(w.SourceAddress) {
			continue
		}
		ok, e := allow(telemetry.Normalized{AgentID: a.AgentID, User: a.User, SourceIP: w.SourceAddress, DestinationIP: w.DestinationAddress})
		if e != nil {
			return e
		}
		if !ok {
			continue
		}
		rows, e := tx.QueryContext(ctx, `SELECT payload FROM normalized_events WHERE class IN ('network_flow','network_alert') AND status='parsed' AND source_ip=? AND event_time>=? AND event_time<=? ORDER BY event_time,sequence LIMIT 101`, w.SourceAddress, stamp(a.At.Add(-5*time.Second)), stamp(a.At.Add(30*time.Minute)))
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
			if !sensorMatches(a, n) {
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
			basis := ""
			if n.Network.Sampled {
				basis = "sFlow: выборочный пакет; использовано время приёма сенсором, задержка экспорта неизвестна. "
			}
			c.Links = append(c.Links, telemetry.ChainLink{From: a.EventID, To: n.ID, Kind: "sensor_observation", Basis: basis + "Независимое сетевое наблюдение: совпали TCP-адреса и порты, время WFP входит в наблюдаемый интервал с допуском 5 секунд. Сенсор — наблюдатель, не конечный узел. NAT, повторное использование портов, sampling и часы ограничивают вывод; принадлежность учётке и факт атаки не установлены."})
		}
	}
	return nil
}
