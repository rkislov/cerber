// SPDX-License-Identifier: Apache-2.0
package ingest_test

import (
	"bytes"
	"encoding/json"
	"github.com/rkislov/cerber/internal/ingest"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func heartbeat() ingest.Heartbeat {
	return ingest.Heartbeat{SchemaVersion: 1, AgentID: "agent-1", ObservedAt: time.Now().UTC(), Platform: "windows", Architecture: "amd64", QueueKnown: true, QueueReports: 1, QueueBytes: 100, CollectionStatus: "partial", DeliveryStatus: "error"}
}
func TestHeartbeatContactAndInventoryRemainIndependent(t *testing.T) {
	s, asset, c := setup(t)
	server := httptest.NewServer(ingest.NewHandler(s))
	defer server.Close()
	client, err := ingest.NewClient(server.URL, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	h := heartbeat()
	future := time.Now().Add(48 * time.Hour)
	h.ObservedAt = future
	h.LastCollectionAt = &future
	receipt, err := client.Heartbeat(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(receipt.ReceivedAt) > time.Second || !receipt.ObservedAt.Equal(future) {
		t.Fatal(receipt)
	}
	statuses, err := s.AgentStatuses(ctx, asset, "", 10)
	if err != nil || len(statuses) != 1 {
		t.Fatal(statuses, err)
	}
	v := statuses[0]
	v.Evaluate(time.Now(), 15*time.Minute, time.Hour)
	if v.ContactStatus != "online" || v.InventoryStatus != "missing" || v.HealthStatus != "fresh" || v.QueueStatus != "pending" {
		t.Fatal(v)
	}
	before, _ := s.Events(ctx, 0, 100)
	h.QueueReports = 2
	h.ObservedAt = time.Now()
	if _, err = client.Heartbeat(ctx, h); err != nil {
		t.Fatal(err)
	}
	after, _ := s.Events(ctx, 0, 100)
	if len(before) != len(after) {
		t.Fatal("heartbeat/counter churn flooded outbox")
	}
	h.QueueReports = 100
	if _, err = client.Heartbeat(ctx, h); err != nil {
		t.Fatal(err)
	}
	after, _ = s.Events(ctx, 0, 100)
	if len(after) != len(before)+1 || after[len(after)-1].Kind != "agent.health_changed" {
		t.Fatal(after)
	}
	r := report("windows")
	r.Snapshot.CollectedAt = time.Now().Add(-48 * time.Hour)
	if _, err = client.Send(ctx, r); err != nil {
		t.Fatal(err)
	}
	statuses, _ = s.AgentStatuses(ctx, asset, "", 10)
	v = statuses[0]
	v.Evaluate(time.Now(), 15*time.Minute, time.Hour)
	if v.ContactStatus != "online" || v.InventoryStatus != "stale" || v.QueueStatus != "full" {
		t.Fatal(v)
	}
	// Stale heartbeat health is not treated as current even if a report keeps contact fresh.
	v.LastHeartbeatAt = pointerTime(time.Now().Add(-time.Hour))
	v.Evaluate(time.Now(), 15*time.Minute, time.Hour)
	if v.HealthStatus != "stale" || v.QueueStatus != "unknown" || v.ContactStatus != "online" {
		t.Fatal(v)
	}
	if err = s.RevokeAgent(ctx, c.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Heartbeat(ctx, h); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatal("revoked heartbeat accepted", err)
	}
}
func pointerTime(v time.Time) *time.Time { return &v }
func TestAgentStatusAgeAndRevocation(t *testing.T) {
	now := time.Now().UTC()
	v := ingest.AgentStatus{}
	v.Evaluate(now, time.Minute, time.Hour)
	if v.ContactStatus != "never_seen" || v.InventoryStatus != "missing" {
		t.Fatal(v)
	}
	v.LastSeenAt = pointerTime(now.Add(-2 * time.Minute))
	v.LatestInventoryAt = pointerTime(now.Add(-2 * time.Hour))
	v.LatestInventoryID = "snapshot"
	v.Evaluate(now, time.Minute, time.Hour)
	if v.ContactStatus != "offline" || v.InventoryStatus != "stale" {
		t.Fatal(v)
	}
	v.Revoked = true
	v.Evaluate(now, time.Minute, time.Hour)
	if v.ContactStatus != "revoked" {
		t.Fatal(v)
	}
}
func TestHeartbeatHTTPValidationAndAuthentication(t *testing.T) {
	s, _, c := setup(t)
	server := httptest.NewServer(ingest.NewHandler(s))
	defer server.Close()
	valid, _ := json.Marshal(heartbeat())
	bad := heartbeat()
	bad.AgentID = "other"
	mismatch, _ := json.Marshal(bad)
	for _, tc := range []struct {
		body, token string
		want        int
	}{{`{"unknown":true}`, c.Token, 400}, {string(valid) + ` {}`, c.Token, 400}, {string(mismatch), c.Token, 403}, {`{"pad":"` + strings.Repeat("x", 5000) + `"}`, c.Token, 413}, {string(valid), strings.Repeat("c", 64), 401}} {
		req, _ := http.NewRequest("POST", server.URL+"/v1/agent/heartbeat", strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer "+tc.token)
		req.Header.Set("X-Cerber-Agent", c.AgentID)
		req.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != tc.want {
			t.Fatal(response.StatusCode, tc.want)
		}
	}
	statuses, _ := s.AgentStatuses(ctx, "", "", 10)
	if statuses[0].LastSeenAt != nil {
		t.Fatal("invalid heartbeat changed contact")
	}
}
func TestHeartbeatRejectsForgedReceipt(t *testing.T) {
	c := ingest.Credentials{AgentID: "agent-1", Token: strings.Repeat("a", 64)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ingest.HeartbeatReceipt{AgentID: "another", ObservedAt: time.Now(), ReceivedAt: time.Now()})
	}))
	defer server.Close()
	client, err := ingest.NewClient(server.URL, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err = client.Heartbeat(ctx, heartbeat()); err == nil {
		t.Fatal("accepted forged receipt")
	}
	output, _ := json.Marshal(heartbeat())
	if bytes.Contains(output, []byte(c.Token)) {
		t.Fatal("token in health payload")
	}
}
