// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"errors"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/telemetry"
	"testing"
	"time"
)

type failedHealthQueue struct{}

func (failedHealthQueue) AgentQueueUsage(context.Context, string) (int64, int64, error) {
	return 0, 0, errors.New("locked database")
}

type blockingHeartbeat struct{ called chan ingest.Heartbeat }

func (s blockingHeartbeat) Heartbeat(ctx context.Context, h ingest.Heartbeat) (ingest.HeartbeatReceipt, error) {
	s.called <- h
	<-ctx.Done()
	return ingest.HeartbeatReceipt{}, ctx.Err()
}
func TestHeartbeatSendsUnknownQueueAndCancelsWhileDeliveryBlocked(t *testing.T) {
	health := &Health{}
	at := time.Now().UTC()
	health.Collected(inventory.Snapshot{CollectedAt: at, Coverage: []inventory.Coverage{{Section: "os", Status: "partial"}}}, nil)
	health.Delivered(0, errors.New("offline"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := make(chan ingest.Heartbeat, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunHeartbeats(ctx, failedHealthQueue{}, blockingHeartbeat{called}, "agent", health, time.Minute, func(error) { t.Error("reported cancellation as network failure") })
	}()
	select {
	case h := <-called:
		if h.QueueKnown || h.CollectionStatus != "partial" || h.DeliveryStatus != "error" || h.LastCollectionAt == nil || !h.LastCollectionAt.Equal(at) {
			t.Fatal(h)
		}
	case <-time.After(time.Second):
		t.Fatal("heartbeat suppressed by failed queue query")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not stop")
	}
}

func TestEventHealthRetainsSuccessAndClonesState(t *testing.T) {
	h := &Health{}
	now := time.Now().UTC()
	v := telemetry.CollectorHealth{Enabled: true, ObservedAt: now, Delivery: "ok", LastDeliveryAt: &now, Sources: []telemetry.SourceHealth{{Source: "journald", State: "ok", LastReadAt: &now}}}
	h.EventsObserved(v)
	v.Sources[0].State = "error"
	future := now.Add(time.Hour)
	h.EventsObserved(telemetry.CollectorHealth{Enabled: true, ObservedAt: future, Delivery: "error", Sources: []telemetry.SourceHealth{{Source: "journald", State: "error", Code: "source_read_failed"}}})
	b := h.Snapshot("agent")
	if b.Events == nil || !b.Events.LastDeliveryAt.Equal(now) || !b.Events.Sources[0].LastReadAt.Equal(now) || b.Events.Sources[0].State != "error" {
		t.Fatal(b.Events)
	}
	*b.Events.LastDeliveryAt = future
	b.Events.Sources[0].State = "blocked"
	again := h.Snapshot("agent")
	if !again.Events.LastDeliveryAt.Equal(now) || again.Events.Sources[0].State != "error" {
		t.Fatal("shared heartbeat memory")
	}
}
