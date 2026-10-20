// SPDX-License-Identifier: Apache-2.0
package eventcollector

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/eventstore"
	"github.com/rkislov/cerber/internal/telemetry"
	"testing"
	"time"
)

type healthSource struct {
	records []telemetry.Raw
	err     error
}

func (s healthSource) Name() string                                          { return "journald" }
func (s healthSource) Read(context.Context, string) ([]telemetry.Raw, error) { return s.records, s.err }

type healthSender struct{ err error }

func (s healthSender) SendEvents(_ context.Context, b telemetry.Batch) (telemetry.Receipt, error) {
	return telemetry.Receipt{BatchID: b.ID, AgentID: b.AgentID, Count: len(b.Records), ReceivedAt: time.Now()}, s.err
}

type fullSpool struct{ *eventstore.Store }

func (s fullSpool) Enqueue(context.Context, telemetry.Batch, string, string, string) error {
	return telemetry.ErrFull
}
func TestEventHealthDistinguishesReadDeliveryAndBackpressure(t *testing.T) {
	ctx := context.Background()
	s, e := eventstore.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	onError := func(error) {}
	a := "agent"
	bad := Cycle(ctx, s, healthSender{}, a, []Source{healthSource{err: errors.New("secret diagnostic stays local")}}, onError)
	if bad.Validate() != nil || bad.Sources[0].State != "error" || bad.Sources[0].Code != "source_read_failed" || !bad.QueueKnown {
		t.Fatal(bad)
	}
	source := healthSource{records: []telemetry.Raw{{ID: telemetry.ID("record"), Source: "journald", Cursor: "one", ObservedAt: time.Now(), Data: json.RawMessage(`{"MESSAGE":"Событие с кириллицей"}`)}}}
	v := Cycle(ctx, s, healthSender{err: errors.New("offline")}, a, []Source{source}, onError)
	if v.Validate() != nil || v.Sources[0].State != "ok" || v.Delivery != "error" || v.QueueBatches != 1 {
		t.Fatal(v)
	}
	b, e := s.NextBatch(ctx, a)
	if e != nil {
		t.Fatal(e)
	}
	data, _ := json.Marshal(b)
	if v.QueueBytes != int64(len(data)) {
		t.Fatal("Unicode byte accounting", v.QueueBytes, len(data))
	}
	next := Cycle(ctx, s, healthSender{}, a, []Source{healthSource{}}, onError)
	if next.Validate() != nil || next.QueueBatches != 0 || next.LastDeliveryAt == nil || next.Delivery != "ok" {
		t.Fatal(next)
	}
	blocked := Cycle(ctx, fullSpool{s}, healthSender{}, a, []Source{source}, onError)
	if blocked.Validate() != nil || blocked.Sources[0].State != "blocked" || blocked.Sources[0].Code != "spool_full" {
		t.Fatal(blocked)
	}
}
