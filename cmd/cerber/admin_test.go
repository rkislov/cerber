// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/app"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type readinessWriter struct{ ready chan string }

func (w readinessWriter) Write(b []byte) (int, error) {
	line := string(b)
	if strings.Contains(line, "listening on ") {
		parts := strings.Fields(line)
		select {
		case w.ready <- "http://" + parts[len(parts)-1]:
		default:
		}
	}
	return len(b), nil
}
func TestServerAutomaticallyRaisesAlertsAndServesAdmin(t *testing.T) {
	root := t.TempDir()
	db := filepath.Join(root, "siem.db")
	keyfile := filepath.Join(root, "admin.json")
	var out bytes.Buffer
	if err := run(context.Background(), []string{"siem", "admin-keygen", "-out", keyfile}, &out, &out); err != nil {
		t.Fatal(err)
	}
	key, err := admin.ReadKey(keyfile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), key) {
		t.Fatal("administrator secret leaked")
	}
	if err = run(context.Background(), []string{"siem", "admin-keygen", "-out", keyfile}, &out, &out); err == nil {
		t.Fatal("existing key overwritten")
	}
	s, err := sqlite.Open(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	asset, err := (app.Service{Repo: s}).AddAsset(context.Background(), "192.0.2.77", "server")
	if err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("a", 64)
	if err = s.RegisterAgent(context.Background(), "agent", asset.ID, hash); err != nil {
		t.Fatal(err)
	}
	r := ingest.Report{SchemaVersion: 1, AgentID: "agent", ID: "old-inventory", Snapshot: inventory.Snapshot{SchemaVersion: 1, ID: "old-inventory", AssetID: "local", CollectedAt: time.Now().Add(-2 * time.Hour), Collector: "fixture", Coverage: []inventory.Coverage{{Section: "os", Status: "error"}}}}
	if _, err = s.AcceptReport(context.Background(), "agent", hash, r); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	ready := make(chan string, 1)
	go func() {
		done <- run(ctx, []string{"-db", db, "siem", "serve", "-listen", "127.0.0.1:0", "-admin-key", keyfile, "-inventory-max-age", "1h", "-monitor-interval", "5s"}, io.Discard, readinessWriter{ready})
	}()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(12 * time.Second):
			t.Error("server/monitor did not stop")
		}
	}()
	var base string
	select {
	case base = <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start")
	}
	response, err := http.Get(base + "/admin/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	waitFor(t, 3*time.Second, func() bool {
		items, e := s.Alerts(context.Background(), "active", 0, 10)
		return e == nil && len(items) == 1 && items[0].Kind == "inventory_stale"
	}, "idle server did not automatically alert")
	var registry bytes.Buffer
	if err = run(context.Background(), []string{"-db", db, "siem", "alerts"}, &registry, &registry); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err = json.Unmarshal(registry.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
}
