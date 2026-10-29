// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"fmt"
)

func (s *Store) CorrelationAgentGroups(ctx context.Context, agent string) ([]string, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT g.id FROM agent_groups g JOIN agent_group_members m ON m.group_id=g.id JOIN agents a ON a.id=m.agent_id WHERE m.agent_id=? AND g.archived=0 AND a.revoked=0 ORDER BY g.id LIMIT 1001`, agent)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		out = append(out, id)
	}
	if len(out) > 1000 {
		return nil, fmt.Errorf("correlation group membership exceeds supported bound")
	}
	return out, rows.Err()
}
