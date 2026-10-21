// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"github.com/rkislov/cerber/internal/health"
)

func (s *Store) Health(ctx context.Context) health.Database {
	return health.CheckDB(ctx, s.db, "События SIEM", s.path)
}
