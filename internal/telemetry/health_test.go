// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"testing"
	"time"
)

func TestEventHealthBoundsAndStableTransition(t *testing.T) {
	h := CollectorHealth{Enabled: true, ObservedAt: time.Now(), Delivery: "idle", QueueKnown: true, Sources: []SourceHealth{{Source: "journald", State: "ok"}}}
	if h.Validate() != nil {
		t.Fatal(h)
	}
	key := h.Key()
	h.ObservedAt = h.ObservedAt.Add(time.Hour)
	h.QueueBytes = 123
	if h.Key() != key {
		t.Fatal("timestamps/counters generate audit flood")
	}
	h.Sources[0].State = "error"
	h.Sources[0].Code = "source_read_failed"
	if h.Validate() != nil || h.Key() == key {
		t.Fatal(h)
	}
	h.Sources[0].Code = "arbitrary error with a secret"
	if h.Validate() == nil {
		t.Fatal("unbounded diagnostic accepted")
	}
	h.Sources[0].Code = "source_read_failed"
	h.Sources = append(h.Sources, h.Sources[0])
	if h.Validate() == nil {
		t.Fatal("duplicate source")
	}
	h.Sources = h.Sources[:1]
	h.QueueBatches = 1001
	if h.Validate() == nil {
		t.Fatal("invalid queue limit")
	}
}
