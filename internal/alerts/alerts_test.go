// SPDX-License-Identifier: Apache-2.0
package alerts

import (
	"context"
	"testing"
	"time"
)

type fakeEvaluator struct{ called chan struct{} }

func (s fakeEvaluator) EvaluateAlerts(context.Context, time.Time, Policy) (Result, error) {
	select {
	case s.called <- struct{}{}:
	default:
	}
	return Result{}, nil
}
func TestMonitorRunsWithoutAgentTrafficAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := make(chan struct{}, 1)
	done := make(chan struct{})
	m := &Monitor{Policy: Policy{time.Minute, time.Hour}, Interval: time.Hour}
	go func() { defer close(done); m.Run(ctx, fakeEvaluator{called}, nil) }()
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("idle server did not evaluate alerts")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("monitor did not stop")
	}
	if m.Snapshot().LastSuccessAt == nil {
		t.Fatal("missing monitor state")
	}
}
