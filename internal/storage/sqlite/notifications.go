// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/integrations"
)

func (s *Store) NotificationBatch(ctx context.Context, after int64) ([]integrations.Notification, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT a.sequence,a.id,a.kind,a.agent_id,a.evidence,a.severity,a.raised_at,coalesce(x.name,''),coalesce(x.ip,'') FROM alerts a LEFT JOIN assets x ON x.id=a.asset_id WHERE a.sequence>? AND a.resolved_at IS NULL ORDER BY a.sequence LIMIT 100`, after)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []integrations.Notification{}
	for rows.Next() {
		var n integrations.Notification
		var kind, agent, evidence, severity, raised, name, ip string
		if e = rows.Scan(&n.Sequence, &n.ID, &kind, &agent, &evidence, &severity, &raised, &name, &ip); e != nil {
			return nil, e
		}
		n.Subject = "Предупреждение SIEM: " + alerts.Title(kind)
		n.Body = "Агент: " + agent + "\nID предупреждения: " + n.ID
		var detail alerts.Evidence
		if json.Unmarshal([]byte(evidence), &detail) == nil && detail.Detail != "" {
			n.Body += "\n" + detail.Detail
		}
		at, err := parse(raised)
		if err != nil {
			return nil, err
		}
		n.Details = integrations.MailDetails{Title: alerts.Title(kind), Kind: "alert", Severity: severity, OccurredAt: at, Summary: detail.Detail,
			Fields: []integrations.MailField{
				{Label: "Узел", Value: name}, {Label: "IP-адрес", Value: ip},
				{Label: "Агент", Value: agent, Code: true}, {Label: "ID предупреждения", Value: n.ID, Code: true},
			}}
		out = append(out, n)
	}
	return out, rows.Err()
}
