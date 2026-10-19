// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/app"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCentralCLIEnrollmentAndDelivery(t *testing.T) {
	root := t.TempDir()
	central := filepath.Join(root, "central.db")
	local := filepath.Join(root, "agent.db")
	creds := filepath.Join(root, "credentials.json")
	ctx := context.Background()
	call := func(db string, args ...string) []byte {
		t.Helper()
		var out, diagnostics bytes.Buffer
		if err := run(ctx, append([]string{"-db", db}, args...), &out, &diagnostics); err != nil {
			t.Fatal(args, err, diagnostics.String())
		}
		return out.Bytes()
	}
	var serverAsset, localAsset map[string]any
	json.Unmarshal(call(central, "asset", "add", "-ip", "192.0.2.15"), &serverAsset)
	json.Unmarshal(call(local, "asset", "add", "-ip", "127.0.0.1"), &localAsset)
	enrollment := call(central, "siem", "enroll", "-asset", serverAsset["id"].(string), "-out", creds)
	c, err := readCredentials(creds)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enrollment, []byte(c.Token)) {
		t.Fatal("token leaked to command output")
	}
	var out bytes.Buffer
	if err = run(ctx, []string{"-db", central, "siem", "enroll", "-asset", serverAsset["id"].(string), "-out", creds}, &out, &out); err == nil {
		t.Fatal("overwrote credentials")
	}
	s, err := sqlite.Open(ctx, central)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	server := httptest.NewServer(ingest.NewHandler(s))
	defer server.Close()
	fixture := inventory.Snapshot{SchemaVersion: 1, CollectedAt: time.Now().UTC(), Collector: "fixture", Coverage: []inventory.Coverage{{Section: "updates_available", Status: "partial"}}, OS: inventory.OS{Family: "windows"}, Updates: []inventory.Update{{ID: "wua-id", Title: "Native update", State: "available", Source: "wua"}}}
	data, _ := json.Marshal(fixture)
	file := filepath.Join(root, "snapshot.json")
	os.WriteFile(file, data, 0600)
	var snap inventory.Snapshot
	if err = json.Unmarshal(call(local, "inventory", "import", "-asset", localAsset["id"].(string), "-file", file), &snap); err != nil {
		t.Fatal(err)
	}
	call(local, "agent", "enqueue", "-inventory", snap.ID, "-credentials", creds)
	delivered := call(local, "agent", "flush", "-credentials", creds, "-server", server.URL)
	if !bytes.Contains(delivered, []byte(`"delivered":1`)) {
		t.Fatal(string(delivered))
	}
	history := call(central, "inventory", "list", "-asset", serverAsset["id"].(string))
	if !bytes.Contains(history, []byte(`"update_count": 1`)) {
		t.Fatal(string(history))
	}
	delivered = call(local, "agent", "flush", "-credentials", creds, "-server", server.URL)
	if !bytes.Contains(delivered, []byte(`"delivered":0`)) {
		t.Fatal(string(delivered))
	}
	call(central, "siem", "revoke", "-agent", c.AgentID)
}

func TestNativeLinuxAgent(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("CERBER_NATIVE_SMOKE") != "1" {
		t.Skip("native Linux CI smoke")
	}
	root := t.TempDir()
	ctx := context.Background()
	central, err := sqlite.Open(ctx, filepath.Join(root, "central.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer central.Close()
	asset, err := (app.Service{Repo: central}).AddAsset(ctx, "192.0.2.1", "central")
	if err != nil {
		t.Fatal(err)
	}
	c := ingest.Credentials{AgentID: "native-agent", Token: strings.Repeat("c", 64)}
	if err = central.RegisterAgent(ctx, c.AgentID, asset.ID, ingest.Hash([]byte(c.Token))); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "credentials.json")
	data, _ := json.Marshal(c)
	if err = os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(ingest.NewHandler(central))
	defer server.Close()
	db := filepath.Join(root, "local.db")
	var out, diagnostics bytes.Buffer
	if err = run(ctx, []string{"-db", db, "asset", "add", "-ip", "127.0.0.1"}, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var local map[string]any
	if err = json.Unmarshal(out.Bytes(), &local); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err = run(ctx, []string{"-db", db, "agent", "collect", "-asset", local["id"].(string), "-credentials", file, "-check-package-updates"}, &out, &diagnostics); err != nil {
		t.Fatal(err, diagnostics.String())
	}
	if err = run(ctx, []string{"-db", db, "agent", "flush", "-credentials", file, "-server", server.URL}, &out, &diagnostics); err != nil {
		t.Fatal(err, diagnostics.String())
	}
	history, err := central.Inventories(ctx, asset.ID, 10)
	if err != nil || len(history) != 1 {
		t.Fatal(history, err)
	}
	s, err := central.Inventory(ctx, history[0].ID)
	if err != nil || s.CoverageStatus("packages") != "complete" || s.CoverageStatus("updates_available") != "partial" || len(s.Components) == 0 {
		t.Fatal(s.Coverage, err)
	}
}
