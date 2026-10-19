// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/agent"
	"github.com/rkislov/cerber/internal/app"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func serviceFixture(t *testing.T, root, configDir, stateDir string, install, start, stop func()) {
	t.Helper()
	ctx := context.Background()
	central, err := sqlite.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer central.Close()
	a, err := (app.Service{Repo: central}).AddAsset(ctx, "192.0.2.1", "service-test")
	if err != nil {
		t.Fatal(err)
	}
	c := ingest.Credentials{AgentID: "service-agent", Token: strings.Repeat("e", 64)}
	if err = central.RegisterAgent(ctx, c.AgentID, a.ID, ingest.Hash([]byte(c.Token))); err != nil {
		t.Fatal(err)
	}
	var allow atomic.Bool
	var attempts atomic.Int64
	handler := ingest.NewHandler(central)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		if !allow.Load() {
			http.Error(w, "offline test", 503)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	for _, dir := range []string{root, configDir, stateDir} {
		if err = os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	credentials := filepath.Join(configDir, "credentials.json")
	data, _ := json.Marshal(c)
	if err = os.WriteFile(credentials, data, 0600); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(stateDir, "agent.db")
	local, err := sqlite.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	asset, err := (app.Service{Repo: local}).AddAsset(ctx, "127.0.0.1", "local")
	if err != nil {
		t.Fatal(err)
	}
	svc := app.InventoryService{Store: local}
	snap, err := svc.Import(ctx, asset.ID, inventory.Snapshot{SchemaVersion: 1, Collector: "service-fixture", CollectedAt: time.Now().UTC(), Coverage: []inventory.Coverage{{Section: "updates_available", Status: "partial"}}, Updates: []inventory.Update{{ID: "native", Title: "Update", State: "available", Source: "fixture"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.SaveCheck(ctx, snap, "fixture", []inventory.Availability{{ComponentID: "app", InstalledVersion: "1", AvailableVersion: "2", Status: "update_available"}}); err != nil {
		t.Fatal(err)
	}
	queued, err := local.QueueInventory(ctx, c.AgentID, snap.ID)
	if err != nil {
		t.Fatal(err)
	}
	local.Close()
	config := agent.Config{SchemaVersion: 1, Database: db, AssetID: asset.ID, Credentials: credentials, Server: server.URL, Interval: "1h"}
	data, _ = json.Marshal(config)
	if err = os.WriteFile(filepath.Join(configDir, "agent.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	install()
	start()
	waitFor(t, 30*time.Second, func() bool { return attempts.Load() > 0 }, "service did not attempt delivery")
	stop()
	local, err = sqlite.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := local.NextReport(ctx, c.AgentID)
	local.Close()
	if err != nil || pending.ID != queued.ID {
		t.Fatal("stop discarded pending report", pending.ID, err)
	}
	allow.Store(true)
	start()
	remoteID := ingest.RemoteID(c.AgentID, "inventory", snap.ID)
	waitFor(t, 40*time.Second, func() bool { _, e := central.Inventory(ctx, remoteID); return e == nil }, "restart did not deliver queued report")
	stop()
	local, err = sqlite.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	pending, err = local.NextReport(ctx, c.AgentID)
	if err == nil && pending.ID == queued.ID {
		t.Fatal("delivered report still queued")
	}
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		t.Fatal(err)
	}
	checks, err := central.UpdateChecks(ctx, a.ID, 100)
	if err != nil || len(checks) < 1 {
		t.Fatal("check missing", checks, err)
	}
	if _, err = os.Stat(db); err != nil {
		t.Fatal("state lost", err)
	}
}
func waitFor(t *testing.T, timeout time.Duration, ready func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal(message)
}
