// SPDX-License-Identifier: Apache-2.0
package eventstore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/app"
	"github.com/rkislov/cerber/internal/eventstore"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"github.com/rkislov/cerber/internal/telemetry"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAuthenticatedEventDeliveryAndWebPermissions(t *testing.T) {
	ctx := context.Background()
	control, e := sqlite.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer control.Close()
	journal, e := eventstore.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer journal.Close()
	asset, e := (app.Service{Repo: control}).AddAsset(ctx, "192.0.2.10", "fixture")
	if e != nil {
		t.Fatal(e)
	}
	agentID := "0123456789abcdef0123456789abcdef"
	credentials := ingest.Credentials{AgentID: agentID, Token: strings.Repeat("a", 64)}
	if e = control.RegisterAgent(ctx, agentID, asset.ID, ingest.Hash([]byte(credentials.Token))); e != nil {
		t.Fatal(e)
	}
	hash, _ := admin.HashPassword("fixture-only-password")
	for _, u := range []admin.User{{Username: "root", Role: "administrator"}, {Username: "operator", Role: "operator"}, {Username: "viewer", Role: "viewer"}} {
		if e = control.AdminCommand(ctx, admin.Command{Action: "user.create", Username: u.Username, Role: u.Role, PasswordHash: hash}); e != nil {
			t.Fatal(e)
		}
	}
	h, e := admin.NewHandler(control, "", admin.Options{Policy: alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}, Events: journal})
	if e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	mux.Handle("/admin/", h)
	mux.Handle("/v1/agent/events", ingest.NewEventHandler(control, journal))
	server := httptest.NewServer(mux)
	defer server.Close()
	client, e := ingest.NewClient(server.URL, credentials, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	p, _ := json.Marshal(map[string]any{"event_id": 1102, "time": time.Now().UTC().Format(time.RFC3339Nano), "provider": "Microsoft-Windows-Security-Auditing"})
	b := telemetry.Batch{SchemaVersion: 1, ID: telemetry.ID("batch"), AgentID: agentID, Records: []telemetry.Raw{{ID: telemetry.ID("event"), Source: "windows:Security", Cursor: "record-1", ObservedAt: time.Now().UTC(), Data: p}}}
	if _, e = client.SendEvents(ctx, b); e != nil {
		t.Fatal(e)
	}
	if _, e = client.SendEvents(ctx, b); e != nil {
		t.Fatal("retry", e)
	}
	if e = journal.Step(ctx); e != nil {
		t.Fatal(e)
	}
	ds, e := journal.ReadDetections(ctx, 0, 100)
	if e != nil || len(ds) != 1 {
		t.Fatal(ds, e)
	}
	request := func(method, path string, payload any, cookie *http.Cookie, csrf string) (int, []byte, *http.Response) {
		t.Helper()
		p, _ := json.Marshal(payload)
		r, _ := http.NewRequest(method, server.URL+path, bytes.NewReader(p))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", server.URL)
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		res, e := server.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		data, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res.StatusCode, data, res
	}
	if code, _, _ := request("GET", "/admin/api/security-events", nil, nil, ""); code != 401 {
		t.Fatal("unauthenticated read", code)
	}
	for _, name := range []string{"viewer", "operator"} {
		code, _, res := request("POST", "/admin/login", map[string]string{"username": name, "password": "fixture-only-password"}, nil, "")
		if code != 200 {
			t.Fatal(code)
		}
		cookie := res.Cookies()[0]
		_, p, _ := request("GET", "/admin/api/session", nil, cookie, "")
		var session map[string]string
		json.Unmarshal(p, &session)
		code, p, _ = request("GET", "/admin/api/security-events", nil, cookie, "")
		if code != 200 || !strings.Contains(string(p), "audit") {
			t.Fatal(code, string(p))
		}
		code, _, _ = request("POST", "/admin/api/detections", map[string]string{"id": ds[0].ID}, cookie, "")
		if code != 403 {
			t.Fatal("missing csrf", code)
		}
		code, _, _ = request("POST", "/admin/api/detections", map[string]string{"id": ds[0].ID}, cookie, session["csrf"])
		want := 200
		if name == "viewer" {
			want = 403
		}
		if code != want {
			t.Fatal("role", name, code)
		}
	}
	if e = control.RevokeAgent(ctx, agentID); e != nil {
		t.Fatal(e)
	}
	if _, e = client.SendEvents(ctx, b); e == nil {
		t.Fatal("revoked agent accepted")
	}
	status, _ := journal.Status(ctx)
	if status.Raw != 1 || status.Detections != 1 {
		t.Fatal("retry duplicated records", status)
	}
}
