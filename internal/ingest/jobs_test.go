// SPDX-License-Identifier: Apache-2.0
package ingest_test

import (
	"context"
	"errors"
	"github.com/rkislov/cerber/internal/agent"
	"github.com/rkislov/cerber/internal/app"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/jobs"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type lostJobAck struct {
	*ingest.Client
	lose bool
}

func (c *lostJobAck) FinishJob(ctx context.Context, r jobs.Result) error {
	err := c.Client.FinishJob(ctx, r)
	if err == nil && c.lose {
		c.lose = false
		return errors.New("fixture acknowledgement lost")
	}
	return err
}
func TestJobDurableResultDeliveryAndCrashRecovery(t *testing.T) {
	central, _, creds := setup(t)
	var deliver atomic.Bool
	handler := ingest.NewHandler(central)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/agent/reports" && !deliver.Load() {
			http.Error(w, "fixture offline", 503)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	client, err := ingest.NewClient(server.URL, creds, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	transport := &lostJobAck{Client: client, lose: true}
	path := filepath.Join(t.TempDir(), "agent.db")
	local, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	asset, err := (app.Service{Repo: local}).AddAsset(ctx, "127.0.0.1", "local")
	if err != nil {
		t.Fatal(err)
	}
	jobID, err := central.JobCommand(ctx, jobs.Command{Action: "run", AgentID: creds.AgentID, Kind: "updates"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	executions := 0
	worker := agent.Worker{Store: local, Client: transport, AgentID: creds.AgentID, Execute: func(runCtx context.Context, j jobs.Job) jobs.Result {
		executions++
		snapshot, e := (app.InventoryService{Store: local}).Import(runCtx, asset.ID, inventory.Snapshot{SchemaVersion: 1, Collector: "fixture", CollectedAt: time.Now().UTC(), OS: inventory.OS{Family: "linux", Name: "Fixture Linux", Version: "1", Architecture: "amd64"}, Coverage: []inventory.Coverage{{Section: "os", Status: "complete"}, {Section: "packages", Status: "complete"}, {Section: "updates_available", Status: "partial"}}})
		if e != nil {
			t.Fatal(e)
		}
		report, e := local.QueueInventory(runCtx, creds.AgentID, snapshot.ID)
		if e != nil {
			t.Fatal(e)
		}
		return agent.JobResult(j, snapshot, report.ID)
	}}
	if err = worker.Step(ctx); err == nil {
		t.Fatal("offline delivery accepted")
	}
	runs, _ := central.Jobs(ctx, creds.AgentID, 0, 101)
	if runs[0].State != "running" || executions != 1 {
		t.Fatal(runs, executions)
	}
	local.Close()
	local, err = sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	worker.Store = local
	worker.Execute = func(context.Context, jobs.Job) jobs.Result {
		t.Fatal("work repeated after restart")
		return jobs.Result{}
	}
	deliver.Store(true)
	if err = worker.Step(ctx); err == nil {
		t.Fatal("lost result acknowledgement not retried")
	}
	runs, _ = central.Jobs(ctx, creds.AgentID, 0, 101)
	if runs[0].ID != jobID || runs[0].State != "partial" || runs[0].InventoryID == "" {
		t.Fatal(runs)
	}
	if _, err = local.LocalJob(ctx, creds.AgentID); err != nil {
		t.Fatal("journal discarded before acknowledgement", err)
	}
	if err = worker.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = local.LocalJob(ctx, creds.AgentID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("journal not released", err)
	}
	// A crash after the durable started marker is reported as interrupted, never rerun.
	next, err := central.JobCommand(ctx, jobs.Command{Action: "run", AgentID: creds.AgentID, Kind: "inventory"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	j, err := client.ClaimJob(ctx)
	if err != nil || j == nil || j.ID != next {
		t.Fatal(j, err)
	}
	if err = local.StartLocalJob(ctx, creds.AgentID, j.ID); err != nil {
		t.Fatal(err)
	}
	if err = worker.Step(ctx); err != nil {
		t.Fatal(err)
	}
	runs, _ = central.Jobs(ctx, creds.AgentID, 0, 101)
	if runs[0].State != "failed" || runs[0].Result.Code != "interrupted" {
		t.Fatal(runs[0])
	}
	if err = central.RevokeAgent(ctx, creds.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, err = client.ClaimJob(ctx); err == nil {
		t.Fatal("revoked agent claimed job")
	}
}
