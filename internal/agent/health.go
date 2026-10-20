// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/inventory"
	"runtime"
	"sync"
	"time"
)

// Health is shared by collection/delivery and the independent heartbeat loop.
// Error text stays in local logs; the wire contract carries bounded status codes.
type Health struct {
	mu                   sync.Mutex
	collection, delivery string
	lastCollection       *time.Time
}

func (h *Health) Collected(snapshot inventory.Snapshot, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err != nil {
		h.collection = "error"
		return
	}
	h.collection = "complete"
	for _, scope := range snapshot.Coverage {
		if scope.Status == "error" {
			h.collection = "error"
			break
		}
		if scope.Status == "partial" {
			h.collection = "partial"
		}
	}
	at := snapshot.CollectedAt
	h.lastCollection = &at
}
func (h *Health) Delivered(count int, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err != nil {
		h.delivery = "error"
	} else if count > 0 {
		h.delivery = "ok"
	}
}
func (h *Health) Snapshot(id string) ingest.Heartbeat {
	h.mu.Lock()
	defer h.mu.Unlock()
	collection, delivery := h.collection, h.delivery
	if collection == "" {
		collection = "not_attempted"
	}
	if delivery == "" {
		delivery = "not_attempted"
	}
	var at *time.Time
	if h.lastCollection != nil {
		value := *h.lastCollection
		at = &value
	}
	return ingest.Heartbeat{SchemaVersion: 1, AgentID: id, ObservedAt: time.Now().UTC(), Platform: runtime.GOOS, Architecture: runtime.GOARCH, CollectionStatus: collection, DeliveryStatus: delivery, LastCollectionAt: at}
}

type HealthQueue interface {
	AgentQueueUsage(context.Context, string) (int64, int64, error)
}
type HeartbeatSender interface {
	Heartbeat(context.Context, ingest.Heartbeat) (ingest.HeartbeatReceipt, error)
}

// RunHeartbeats is synchronous and stops on ctx cancellation. Run it in a tracked
// goroutine so long native scans or blocked report delivery cannot suppress contact.
func RunHeartbeats(ctx context.Context, queue HealthQueue, sender HeartbeatSender, id string, health *Health, interval time.Duration, reportError func(error)) {
	if interval < time.Minute || interval > time.Hour {
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		h := health.Snapshot(id)
		queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		count, size, err := queue.AgentQueueUsage(queryCtx, id)
		cancel()
		if err == nil {
			h.QueueKnown = true
			h.QueueReports = count
			h.QueueBytes = size
		}
		if ctx.Err() != nil {
			return
		}
		_, err = sender.Heartbeat(ctx, h)
		if err != nil && ctx.Err() == nil {
			reportError(err)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
