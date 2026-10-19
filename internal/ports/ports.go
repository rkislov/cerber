// SPDX-License-Identifier: Apache-2.0
// Package ports contains boundaries implemented by infrastructure adapters.
package ports

import (
	"context"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/event"
	"github.com/rkislov/cerber/internal/inventory"
)

// Repository mutations append their supplied event in the same transaction.
// ClaimTask is a compare-and-set queued → running, preventing duplicate execution.
type Repository interface {
	CreateAsset(context.Context, domain.Asset, event.Envelope) error
	Assets(context.Context) ([]domain.Asset, error)
	CreateTarget(context.Context, domain.Target, event.Envelope) error
	Targets(context.Context) ([]domain.Target, error)
	TargetHosts(context.Context, string) ([]domain.Host, error)
	CreateTask(context.Context, domain.Task, event.Envelope) error
	Task(context.Context, string) (domain.Task, error)
	Tasks(context.Context) ([]domain.Task, error)
	ClaimTask(context.Context, string, *domain.KnowledgeSnapshot, event.Envelope) error
	RecordObservation(context.Context, domain.Observation, event.Envelope) error
	FinishTask(context.Context, string, domain.TaskStatus, string, event.Envelope) error
	Observations(context.Context, string) ([]domain.Observation, error)
}

// Scanner reports completed probes to emit. An emit failure must stop scanning.
// A task cancellation must return context.Canceled or context.DeadlineExceeded.
type Scanner interface {
	Scan(context.Context, domain.Task, func(domain.Observation) error) error
}

// EventReader reads the durable outbox in sequence order. Consumers keep their
// own committed cursor. Publication/ack adapters can be added without changing scans.
type EventReader interface {
	Events(context.Context, int64, int) ([]event.Envelope, error)
}

// KnowledgeProvider acquires a local immutable snapshot before a task starts.
// A server-backed adapter must authenticate the manifest, verify downloaded bytes,
// publish the cache atomically and enforce freshness/offline policy before returning.
// Failure leaves the task queued. Implementations must honor ctx.
type KnowledgeProvider interface {
	Acquire(context.Context) (domain.KnowledgeSnapshot, error)
}

// InventoryStore persists historical observations, not an overwriteable current list.
type InventoryStore interface {
	SaveInventory(context.Context, inventory.Snapshot, event.Envelope) error
	Inventory(context.Context, string) (inventory.Snapshot, error)
	Inventories(context.Context, string, int) ([]inventory.Summary, error)
	SaveUpdateCheck(context.Context, inventory.Check, event.Envelope) error
	UpdateChecks(context.Context, string, int) ([]inventory.Check, error)
}
type InventoryCollector interface {
	Collect(context.Context) (inventory.Snapshot, error)
}
