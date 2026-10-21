// SPDX-License-Identifier: Apache-2.0
package ingest_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/rkislov/cerber/internal/agent"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/patch"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSignedPatchSpoolResultRetryAndRevocation(t *testing.T) {
	central, _, creds := setup(t)
	r := report("linux")
	r.Snapshot.PackageManager = "apt"
	r.Checks = nil
	r.Snapshot.Updates[0].Title = "openssl"
	receipt, e := central.AcceptReport(ctx, creds.AgentID, ingest.Hash([]byte(creds.Token)), r)
	if e != nil {
		t.Fatal(e)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	var rejectFinish atomic.Bool
	rejectFinish.Store(true)
	handler := ingest.NewPatchHandler(central, key)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/agent/patches/finish" && rejectFinish.Load() {
			http.Error(w, "fixture unavailable", 503)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	client, e := ingest.NewClient(server.URL, creds, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	j, e := central.PatchCommand(ctx, patch.Command{Action: "preview", AgentID: creds.AgentID, InventoryID: receipt.SnapshotID, UpdateIDs: []string{"native-update"}}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	in, out := t.TempDir(), t.TempDir()
	if e = agent.PatchStep(ctx, client, in, out); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(in, j.Request.ID+".json")
	var ticket patch.Ticket
	if e = patch.ReadJSON(path, &ticket); e != nil {
		t.Fatal(e)
	}
	q, e := ticket.Verify(pub, creds.AgentID, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	result := patch.Result{ID: q.ID, Status: "succeeded", Reboot: "unknown", Items: []patch.Item{{ID: "native-update", Status: "ready", Code: "applicable"}}}
	if e = patch.WriteJSON(filepath.Join(out, q.ID+".json"), result); e != nil {
		t.Fatal(e)
	}
	if e = agent.PatchStep(ctx, client, in, out); e == nil {
		t.Fatal("lost result not retried")
	}
	rejectFinish.Store(false)
	if e = agent.PatchStep(ctx, client, in, out); e != nil {
		t.Fatal(e)
	}
	items, _ := central.PatchJobs(ctx, creds.AgentID)
	if len(items) != 1 || items[0].State != "succeeded" {
		t.Fatal(items)
	}
	if e = agent.PatchStep(ctx, client, in, out); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(path); e != nil {
		t.Fatal(e)
	}
	central.RevokeAgent(ctx, creds.AgentID)
	if _, e = client.ClaimPatch(ctx); e == nil {
		t.Fatal("revoked agent")
	}
}
