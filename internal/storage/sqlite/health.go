// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"github.com/rkislov/cerber/internal/health"
)

func (s *Store) Health(ctx context.Context) health.Database {
	return health.CheckDB(ctx, s.db, "Основная БД", s.path)
}
