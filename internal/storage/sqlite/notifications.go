// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"github.com/rkislov/cerber/internal/integrations"
)

func (s *Store) NotificationBatch(ctx context.Context, after int64) ([]integrations.Notification, error) {
	rows, e := s.db.QueryContext(ctx, "SELECT sequence,id,kind,agent_id FROM alerts WHERE sequence>? AND resolved_at IS NULL ORDER BY sequence LIMIT 100", after)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []integrations.Notification{}
	for rows.Next() {
		var n integrations.Notification
		var kind, agent string
		if e = rows.Scan(&n.Sequence, &n.ID, &kind, &agent); e != nil {
			return nil, e
		}
		n.Subject = "Предупреждение SIEM: " + kind
		n.Body = "Агент: " + agent + "\nID предупреждения: " + n.ID
		out = append(out, n)
	}
	return out, rows.Err()
}
