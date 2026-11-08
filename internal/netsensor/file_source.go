// SPDX-License-Identifier: Apache-2.0
package netsensor

import (
	"context"
	"time"

	"github.com/rkislov/cerber/internal/eventcollector"
	"github.com/rkislov/cerber/internal/flowexport"
	"github.com/rkislov/cerber/internal/telemetry"
)

type eveSource interface {
	eventcollector.Source
	UnreadBytes(context.Context, string) (int64, error)
}

type meteredFile struct {
	source eveSource
	input  Input
}

func (f meteredFile) collect(ctx context.Context, r *Receiver, queued chan<- struct{}, onError func(error)) {
	for ctx.Err() == nil {
		status, records, err := eventcollector.CollectPage(ctx, r.spool, r.agent, f.source)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			onError(err)
		}
		f.recordPage(r, status, records)
		if len(records) > 0 {
			select {
			case queued <- struct{}{}:
			default:
			}
			continue
		}
		// At EOF, an incomplete line, or backpressure, poll at the idle rate.
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (f meteredFile) recordPage(r *Receiver, status telemetry.SourceHealth, records []telemetry.Raw) {
	for _, record := range records {
		r.record(f.input, "local", 0, record.Data, flowexport.Result{}, 1, "", false)
	}
	r.received.Add(uint64(len(records)))
	r.stored.Add(uint64(len(records)))
	r.mu.Lock()
	if status.LastReadAt == nil {
		status.LastReadAt = r.states[status.Source].LastReadAt
	}
	r.states[status.Source] = status
	r.mu.Unlock()

	r.metricsMu.Lock()
	defer r.metricsMu.Unlock()
	input := &r.metrics[f.input.ID].status
	switch {
	case status.State != "ok":
		now := time.Now().UTC()
		input.State, input.LastError, input.LastErrorAt = "error", status.Code, &now
	case input.LastMessageAt != nil:
		input.State = "receiving"
	default:
		input.State = "listening"
	}
}

func (f meteredFile) unreadBytes(ctx context.Context, r *Receiver) *int64 {
	cursor, err := r.spool.SourceCursor(ctx, r.agent, f.source.Name())
	if err != nil {
		return nil
	}
	size, err := f.source.UnreadBytes(ctx, cursor)
	if err != nil {
		return nil
	}
	return &size
}
