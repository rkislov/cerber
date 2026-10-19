// SPDX-License-Identifier: Apache-2.0
package ingest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/rkislov/cerber/internal/agent"
	"github.com/rkislov/cerber/internal/app"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var ctx = context.Background()

func setup(t *testing.T) (*sqlite.Store, string, ingest.Credentials) {
	t.Helper()
	s, err := sqlite.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	a, err := (app.Service{Repo: s}).AddAsset(ctx, "192.0.2.1", "central")
	if err != nil {
		t.Fatal(err)
	}
	c := ingest.Credentials{AgentID: "agent-1", Token: strings.Repeat("a", 64)}
	if err = s.RegisterAgent(ctx, c.AgentID, a.ID, ingest.Hash([]byte(c.Token))); err != nil {
		t.Fatal(err)
	}
	return s, a.ID, c
}
func report(os string) ingest.Report {
	at := time.Now().Add(-time.Minute).UTC()
	return ingest.Report{SchemaVersion: 1, ID: "report-1", AgentID: "agent-1", Snapshot: inventory.Snapshot{SchemaVersion: 1, ID: "local-snapshot", AssetID: "local-asset", CollectedAt: at, Collector: "test-" + os, OS: inventory.OS{Family: os}, Coverage: []inventory.Coverage{{Section: "updates_available", Status: "partial"}}, Updates: []inventory.Update{{ID: "native-update", State: "available", Source: "configured-repository", Title: "Native candidate"}}}, Checks: []inventory.Check{{ID: "local-check", AssetID: "local-asset", InventoryID: "local-snapshot", CheckedAt: at, Source: "test", Results: []inventory.Availability{{ComponentID: "edge", InstalledVersion: "1.0", AvailableVersion: "2.0", Status: "update_available"}}}}}
}
func TestHTTPDeliveryOwnershipAndIdempotency(t *testing.T) {
	for _, os := range []string{"windows", "linux"} {
		t.Run(os, func(t *testing.T) {
			s, asset, c := setup(t)
			server := httptest.NewTLSServer(ingest.NewHandler(s))
			defer server.Close()
			client, err := ingest.NewClient(server.URL, c, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			// Default trust rejects an untrusted server; explicitly trusting its CA works.
			if _, err = client.Send(ctx, report(os)); err == nil {
				t.Fatal("accepted untrusted TLS")
			}
			client, err = ingest.NewClient(server.URL, c, pemCertificate(server))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			r := report(os)
			receipt, err := client.Send(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			if receipt.Duplicate {
				t.Fatal(receipt)
			}
			before, _ := s.Events(ctx, 0, 100)
			var wg sync.WaitGroup
			// Keep retries below the receiver concurrency bound; 429 is valid above it.
			for i := 0; i < 3; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					v, err := client.Send(ctx, r)
					if err != nil || !v.Duplicate {
						t.Errorf("retry: %+v %v", v, err)
					}
				}()
			}
			wg.Wait()
			after, _ := s.Events(ctx, 0, 100)
			if len(before) != len(after) {
				t.Fatal("duplicate events")
			}
			snapshots, err := s.Inventories(ctx, asset, 10)
			if err != nil || len(snapshots) != 1 {
				t.Fatal(snapshots, err)
			}
			snapshot, err := s.Inventory(ctx, receipt.SnapshotID)
			if err != nil || snapshot.AssetID != asset || snapshot.OS.Family != os || len(snapshot.Updates) != 1 {
				t.Fatal(snapshot, err)
			}
			checks, err := s.UpdateChecks(ctx, asset, 10)
			if err != nil || len(checks) != 1 || checks[0].InventoryID != receipt.SnapshotID || checks[0].AssetID != asset {
				t.Fatal(checks, err)
			}
			r.Snapshot.Collector = "changed"
			if _, err = client.Send(ctx, r); err == nil || !strings.Contains(err.Error(), "409") {
				t.Fatal("changed report accepted", err)
			}
			r.ID = "another-report"
			if _, err = client.Send(ctx, r); err == nil || !strings.Contains(err.Error(), "409") {
				t.Fatal("changed immutable snapshot accepted", err)
			}
			if err = s.RevokeAgent(ctx, c.AgentID); err != nil {
				t.Fatal(err)
			}
			if _, err = client.Send(ctx, report(os)); err == nil || !strings.Contains(err.Error(), "401") {
				t.Fatal("revoked agent accepted", err)
			}
		})
	}
}
func TestAtomicRollbackAndNewChecks(t *testing.T) {
	s, asset, c := setup(t)
	r := report("linux")
	hash := ingest.Hash([]byte(c.Token))
	first, err := s.AcceptReport(ctx, c.AgentID, hash, r)
	if err != nil {
		t.Fatal(err)
	}
	r.ID = "report-2"
	r.Checks[0].Results[0].Status = "unknown"
	r.Checks = append([]inventory.Check{{ID: "new-check", AssetID: r.Snapshot.AssetID, InventoryID: r.Snapshot.ID, Source: "new", CheckedAt: time.Now()}}, r.Checks...)
	if _, err = s.AcceptReport(ctx, c.AgentID, hash, r); !errors.Is(err, domain.ErrConflict) {
		t.Fatal(err)
	}
	checks, _ := s.UpdateChecks(ctx, asset, 100)
	if len(checks) != 1 {
		t.Fatal("partial commit", checks)
	}
	r.Checks = r.Checks[:1]
	v, err := s.AcceptReport(ctx, c.AgentID, hash, r)
	if err != nil || v.SnapshotID != first.SnapshotID {
		t.Fatal(v, err)
	}
	checks, _ = s.UpdateChecks(ctx, asset, 100)
	if len(checks) != 2 {
		t.Fatal(checks)
	}
}
func TestPersistentQueueLostAcknowledgement(t *testing.T) {
	serverStore, asset, c := setup(t)
	real := ingest.NewHandler(serverStore)
	drop := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if drop {
			drop = false
			rec := httptest.NewRecorder()
			real.ServeHTTP(rec, r)
			if rec.Code != 200 {
				t.Errorf("commit: %s", rec.Body.String())
			}
			http.Error(w, "ack lost", 503)
			return
		}
		real.ServeHTTP(w, r)
	}))
	defer server.Close()
	client, err := ingest.NewClient(server.URL, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	path := filepath.Join(t.TempDir(), "agent.db")
	local, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := (app.Service{Repo: local}).AddAsset(ctx, "127.0.0.1", "local")
	if err != nil {
		t.Fatal(err)
	}
	svc := app.InventoryService{Store: local}
	snap, err := svc.Import(ctx, a.ID, report("windows").Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.SaveCheck(ctx, snap, "test", report("windows").Checks[0].Results); err != nil {
		t.Fatal(err)
	}
	queued, err := local.QueueInventory(ctx, c.AgentID, snap.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := agent.Flush(ctx, local, client, c.AgentID); err == nil || n != 0 {
		t.Fatal(n, err)
	}
	local.Close()
	local, err = sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	pending, err := local.NextReport(ctx, c.AgentID)
	if err != nil || pending.ID != queued.ID {
		t.Fatal(pending, err)
	}
	if n, err := agent.Flush(ctx, local, client, c.AgentID); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if _, err = local.NextReport(ctx, c.AgentID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("queue not acknowledged", err)
	}
	history, _ := serverStore.Inventories(ctx, asset, 10)
	if len(history) != 1 {
		t.Fatal(history)
	}
}
func TestHTTPRejectsUnboundAndMalformedReports(t *testing.T) {
	s, asset, c := setup(t)
	server := httptest.NewServer(ingest.NewHandler(s))
	defer server.Close()
	for _, tc := range []struct {
		name, token, agent, body string
		want                     int
	}{
		{"bad-token", strings.Repeat("b", 64), c.AgentID, `{}`, 401},
		{"unknown-agent", c.Token, "unknown", `{}`, 401},
		{"unknown-field", c.Token, c.AgentID, `{"unexpected":1}`, 400},
		{"trailing-json", c.Token, c.AgentID, `{} {}`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", server.URL+"/v1/agent/reports", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Cerber-Agent", tc.agent)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatal(resp.StatusCode)
			}
		})
	}
	r := report("linux")
	r.Checks[0].InventoryID = "other-inventory"
	data, _ := json.Marshal(r)
	req, _ := http.NewRequest("POST", server.URL+"/v1/agent/reports", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cerber-Agent", c.AgentID)
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatal(resp.StatusCode)
	}
	history, _ := s.Inventories(ctx, asset, 10)
	if len(history) != 0 {
		t.Fatal("invalid report committed")
	}
}
func TestClientRefusesUnsafeOrigins(t *testing.T) {
	c := ingest.Credentials{AgentID: "agent", Token: strings.Repeat("a", 64)}
	for _, origin := range []string{"http://siem.example", "http://localhost:8790", "https://user:secret@siem.example", "https://siem.example/path", "https://siem.example/?token=secret"} {
		if _, err := ingest.NewClient(origin, c, nil); err == nil {
			t.Fatal("accepted", origin)
		}
	}
}

func pemCertificate(s *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
}

func TestQueueCapacityAndAgentIsolation(t *testing.T) {
	s, asset, c := setup(t)
	snap, err := (app.InventoryService{Store: s}).Import(ctx, asset, report("linux").Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if _, err = s.QueueInventory(ctx, c.AgentID, snap.ID); err != nil {
			t.Fatal(i, err)
		}
	}
	if _, err = s.QueueInventory(ctx, c.AgentID, snap.ID); err == nil {
		t.Fatal("queue grew beyond capacity")
	}
	if count, _, err := s.QueueUsage(ctx); err != nil || count != 100 {
		t.Fatal(count, err)
	}
	if _, err = s.NextReport(ctx, "different-agent"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("cross-agent queue read", err)
	}
}
func TestRedirectDoesNotForwardCredentials(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("redirect followed") }))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer origin.Close()
	c := ingest.Credentials{AgentID: "agent-1", Token: strings.Repeat("a", 64)}
	client, err := ingest.NewClient(origin.URL, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err = client.Send(ctx, report("windows")); err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatal(err)
	}
}
