// SPDX-License-Identifier: Apache-2.0
package jobs

import (
	"context"
	"errors"
	"testing"
	"time"
)

type evaluator func(context.Context, time.Time) error

func (f evaluator) AdvanceJobs(ctx context.Context, now time.Time) error { return f(ctx, now) }
func TestSchedulerMonitorReportsSuccessAndFailureAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Monitor{}
	m.Run(ctx, evaluator(func(context.Context, time.Time) error { cancel(); return nil }), func(error) { t.Fatal("reported canceled success as failure") })
	s := m.Snapshot()
	if s.Failed || s.LastSuccessAt == nil {
		t.Fatal(s)
	}
	*s.LastSuccessAt = time.Time{}
	if m.Snapshot().LastSuccessAt.IsZero() {
		t.Fatal("snapshot aliases live state")
	}
	ctx, cancel = context.WithCancel(context.Background())
	m = &Monitor{}
	logs := 0
	m.Run(ctx, evaluator(func(context.Context, time.Time) error { return errors.New("fixture database unavailable") }), func(error) { logs++; cancel() })
	s = m.Snapshot()
	if !s.Failed || s.LastSuccessAt != nil || logs != 1 {
		t.Fatal(s, logs)
	}
}
