package app_test

import (
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/app"
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"path/filepath"
	"testing"
	"time"
)

func TestInventoryHistoryEventsAndLateArrival(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db")
	store, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	asset, err := (app.Service{Repo: store}).AddAsset(ctx, "127.0.0.1", "local")
	if err != nil {
		t.Fatal(err)
	}
	service := app.InventoryService{Assets: store, Store: store}
	data := inventory.Snapshot{SchemaVersion: 1, Collector: "test", CollectedAt: time.Now().Add(-time.Hour).UTC(), Coverage: []inventory.Coverage{{Section: "applications", Status: "complete"}}, Components: []inventory.Component{{ID: "app", Kind: "application", Name: "App", Version: "1.0", Source: "test"}}}
	first, err := service.Import(ctx, asset.ID, data)
	if err != nil {
		t.Fatal(err)
	}
	data.Components[0].Version = "2.0"
	data.CollectedAt = data.CollectedAt.Add(time.Minute)
	second, err := service.Import(ctx, asset.ID, data)
	if err != nil {
		t.Fatal(err)
	}
	data.CollectedAt = data.CollectedAt.Add(-2 * time.Minute)
	if _, err = service.Import(ctx, asset.ID, data); err != nil {
		t.Fatal(err)
	}
	history, err := store.Inventories(ctx, asset.ID, 10)
	if err != nil || len(history) != 3 || history[0].ID != second.ID || history[0].ComponentCount != 1 {
		t.Fatal(history, err)
	}
	check, err := service.SaveCheck(ctx, second, "test", []inventory.Availability{{ComponentID: "app", Status: "update_available", AvailableVersion: "3.0"}})
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	store, err = sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	a, err := store.Inventory(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.Inventory(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := inventory.Diff(a, b)
	if err != nil || len(changes) != 1 || changes[0].Type != "changed" {
		t.Fatal(changes, err)
	}
	checks, err := store.UpdateChecks(ctx, asset.ID, 10)
	if err != nil || len(checks) != 1 || checks[0].ID != check.ID {
		t.Fatal(checks, err)
	}
	events, err := store.Events(ctx, 0, 100)
	if err != nil || len(events) != 5 {
		t.Fatal(events, err)
	}
	if events[1].Kind != "inventory.recorded" || events[4].Kind != "updates.checked" {
		t.Fatal(events)
	}
	var payload map[string]any
	if err = json.Unmarshal(events[1].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["snapshot_id"] != first.ID {
		t.Fatal(payload)
	}
}
func TestLocalCollectionRejectsNonLocalAssetBeforeCollectorRuns(t *testing.T) {
	store, base, _ := fixture(t)
	remote, err := base.AddAsset(context.Background(), "192.0.2.17", "remote")
	if err != nil {
		t.Fatal(err)
	}
	service := app.InventoryService{Store: store, Assets: store}
	if _, err = service.CollectLocal(context.Background(), remote.ID, panicCollector{}); err == nil {
		t.Fatal("attached local inventory to remote asset")
	}
}

type panicCollector struct{}

func (panicCollector) Collect(context.Context) (inventory.Snapshot, error) {
	panic("collector should not run")
}
