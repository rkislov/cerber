// SPDX-License-Identifier: Apache-2.0
package netsensor

import (
	"context"
	"github.com/rkislov/cerber/internal/eventcollector"
	"github.com/rkislov/cerber/internal/flowexport"
	"github.com/rkislov/cerber/internal/telemetry"
)

// File metrics count durable enqueues, not read attempts or SIEM acknowledgements.
// Source.Read and commitMetrics run sequentially in the collector cycle.
type meteredFile struct {
	eventcollector.Source
	input   Input
	records []telemetry.Raw
}

func (f *meteredFile) Read(ctx context.Context, cursor string) ([]telemetry.Raw, error) {
	f.records = nil
	v, e := f.Source.Read(ctx, cursor)
	if e == nil {
		f.records = v
	}
	return v, e
}
func (f *meteredFile) commitMetrics(r *Receiver, health []telemetry.SourceHealth) {
	defer func() { f.records = nil }()
	for _, h := range health {
		if h.Source == f.Name() && h.State == "ok" {
			for _, v := range f.records {
				r.record(f.input, "local", 0, v.Data, flowexport.Result{}, 1, "", false)
				r.received.Add(1)
				r.stored.Add(1)
			}
			return
		}
	}
}
