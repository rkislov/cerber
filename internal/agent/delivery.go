// SPDX-License-Identifier: Apache-2.0
// Package agent delivers durable queued reports independently of collection adapters.
package agent

import (
	"context"
	"errors"
	"fmt"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/ingest"
)

type Queue interface {
	NextReport(context.Context, string) (ingest.Report, error)
	AckReport(context.Context, string, string) error
}
type Sender interface {
	Send(context.Context, ingest.Report) (ingest.Receipt, error)
}

func Flush(ctx context.Context, q Queue, s Sender, id string) (int, error) {
	count := 0
	for count < 100 {
		r, err := q.NextReport(ctx, id)
		if errors.Is(err, domain.ErrNotFound) {
			return count, nil
		}
		if err != nil {
			return count, err
		}
		receipt, err := s.Send(ctx, r)
		if err != nil {
			return count, err
		}
		if receipt.ReportID != r.ID || receipt.AgentID != id || receipt.SnapshotID != ingest.RemoteID(id, "inventory", r.Snapshot.ID) || receipt.ReceivedAt.IsZero() {
			return count, fmt.Errorf("delivery receipt mismatch; report retained")
		}
		if err = q.AckReport(ctx, id, r.ID); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}
