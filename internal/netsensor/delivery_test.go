// SPDX-License-Identifier: Apache-2.0
package netsensor

import (
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/eventstore"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/telemetry"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type sensorBinding struct{ id, hash string }

func (b sensorBinding) AgentBinding(_ context.Context, id, hash string) (string, error) {
	if id != b.id || hash != b.hash {
		return "", ingest.ErrUnauthorized
	}
	return "observer-asset", nil
}

func TestIndependentSensorFileDeliveryOverAuthenticatedAPI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	journal, e := eventstore.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer journal.Close()
	credentials := ingest.Credentials{AgentID: "sensor-test", Token: strings.Repeat("a", 64)}
	server := httptest.NewServer(ingest.NewEventHandler(sensorBinding{credentials.AgentID, ingest.Hash([]byte(credentials.Token))}, journal))
	defer server.Close()
	dir := t.TempDir()
	secret := filepath.Join(dir, "credentials.json")
	p, _ := json.Marshal(credentials)
	if e = os.WriteFile(secret, p, 0600); e != nil {
		t.Fatal(e)
	}
	event := map[string]any{"timestamp": time.Now().UTC().Format(time.RFC3339Nano), "event_type": "alert", "src_ip": "192.0.2.1", "dest_ip": "192.0.2.2", "src_port": 12345, "dest_port": 445, "proto": "TCP", "alert": map[string]any{"signature_id": 42, "signature": "Local test fixture", "severity": 2}}
	p, _ = json.Marshal(event)
	file := filepath.Join(dir, "eve.json")
	if e = os.WriteFile(file, append(p, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	c := Config{SchemaVersion: 1, Server: server.URL, Credentials: secret, Spool: filepath.Join(dir, "queue.db"), Inputs: []Input{{ID: "tap", Format: "suricata", Protocol: "file", Path: file}}}
	q, e := eventstore.Open(ctx, c.Spool)
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c, io.Discard); close(done) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(5 * time.Second)
	received := false
	for time.Now().Before(deadline) {
		status, e := journal.Status(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if status.Raw == 1 {
			// Server persistence precedes HTTP ACK and the sensor's durable dequeue.
			// Wait for both before cancellation, which can interrupt either step.
			count, _, err := q.EventQueueUsage(ctx, credentials.AgentID)
			if err != nil {
				t.Fatal(err)
			}
			if count == 0 {
				received = true
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if !received {
		t.Fatal("separate sensor did not deliver")
	}
	ctx = context.Background()
	if e = journal.Step(ctx); e != nil {
		t.Fatal(e)
	}
	n, e := journal.ReadEvents(ctx, telemetry.Query{Class: "network_alert", Source: "network:suricata", Limit: 10})
	if e != nil || len(n) != 1 {
		t.Fatal(n, e)
	}
	if n[0].AssetID != "observer-asset" || n[0].Network.Exporter != "local" || n[0].User != "" || n[0].Identity != nil {
		t.Fatal("observer attribution corrupted", n[0])
	}
	count, _, e := q.EventQueueUsage(ctx, credentials.AgentID)
	if e != nil || count != 0 {
		t.Fatal("ACK did not drain queue", count, e)
	}
}
