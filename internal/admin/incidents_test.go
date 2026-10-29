// SPDX-License-Identifier: Apache-2.0
package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/eventstore"
	"github.com/rkislov/cerber/internal/incidents"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"github.com/rkislov/cerber/internal/telemetry"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIncidentAPIAnalystScopeCSRFAndHistory(t *testing.T) {
	ctx := context.Background()
	control, e := sqlite.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer control.Close()
	events, e := eventstore.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer events.Close()
	hash, _ := admin.HashPassword("fixture-only-password")
	for _, u := range []admin.User{{Username: "root", Role: "administrator"}, {Username: "analyst", Role: "analyst"}, {Username: "reader", Role: "viewer"}, {Username: "disabled", Role: "analyst", Disabled: true}} {
		if e = control.AdminCommand(ctx, admin.Command{Action: "user.create", Username: u.Username, Role: u.Role, Disabled: u.Disabled, PasswordHash: hash}); e != nil {
			t.Fatal(e)
		}
	}
	now := time.Now()
	p, _ := json.Marshal(map[string]any{"event_id": 1102, "time": now.UTC().Format(time.RFC3339Nano), "provider": "Microsoft-Windows-Security-Auditing"})
	b := telemetry.Batch{SchemaVersion: 1, ID: telemetry.ID("batch"), AgentID: "agent", Records: []telemetry.Raw{{ID: telemetry.ID("event"), Source: "windows:Security", Cursor: "1", ObservedAt: now, Data: p}}}
	if _, e = events.Accept(ctx, "agent", "asset", b); e != nil {
		t.Fatal(e)
	}
	if e = events.Step(ctx); e != nil {
		t.Fatal(e)
	}
	ds, _ := events.ReadDetections(ctx, 0, 100)
	handler, e := admin.NewHandler(control, "", admin.Options{Events: events, Policy: alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	type session struct {
		cookie *http.Cookie
		csrf   string
	}
	request := func(u session, method, path string, body any, csrf bool) (int, []byte, *http.Response) {
		t.Helper()
		p, _ := json.Marshal(body)
		r, _ := http.NewRequest(method, server.URL+"/admin/"+path, bytes.NewReader(p))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", server.URL)
		if u.cookie != nil {
			r.AddCookie(u.cookie)
		}
		if csrf {
			r.Header.Set("X-CSRF-Token", u.csrf)
		}
		res, e := server.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		data, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res.StatusCode, data, res
	}
	login := func(name string) session {
		t.Helper()
		code, _, res := request(session{}, "POST", "login", map[string]string{"username": name, "password": "fixture-only-password"}, false)
		if code != 200 {
			t.Fatal(code)
		}
		u := session{cookie: res.Cookies()[0]}
		_, p, _ := request(u, "GET", "api/session", nil, false)
		var v map[string]string
		json.Unmarshal(p, &v)
		u.csrf = v["csrf"]
		return u
	}
	analyst, reader := login("analyst"), login("reader")
	if code, _, _ := request(session{}, "GET", "api/incident-graph?id="+telemetry.ID("unknown"), nil, false); code != 401 {
		t.Fatal("anonymous graph", code)
	}
	if code, _, _ := request(reader, "GET", "api/incident-graph?id=invalid", nil, false); code != 400 {
		t.Fatal("invalid graph id", code)
	}
	if code, _, _ := request(reader, "GET", "api/incident-graph?id="+telemetry.ID("unknown"), nil, false); code != 404 {
		t.Fatal("missing graph", code)
	}

	payload := map[string]any{"action": "create", "title": "<script>fixture</script>", "severity": "high", "assignee": "analyst", "detection_id": ds[0].ID}
	if code, _, _ := request(reader, "POST", "api/incidents", payload, true); code != 403 {
		t.Fatal("viewer write", code)
	}
	if code, _, _ := request(analyst, "POST", "api/incidents", payload, false); code != 403 {
		t.Fatal("missing CSRF", code)
	}
	for _, path := range []string{"api/groups", "api/jobs", "api/schedules", "api/users", "api/agents/enroll", "api/acknowledge"} {
		if code, _, _ := request(analyst, "POST", path, map[string]string{"action": "create"}, true); code != 403 {
			t.Fatal("analyst infrastructure write", path, code)
		}
	}
	code, data, _ := request(analyst, "POST", "api/incidents", payload, true)
	if code != 200 || strings.Contains(string(data), "<script>") {
		t.Fatal(code, string(data))
	}
	var c incidents.Card
	json.Unmarshal(data, &c)
	if c.CreatedBy != "analyst" || c.DetectionCount != 1 {
		t.Fatal(c)
	}
	for _, u := range []session{reader, analyst} {
		if code, data, _ := request(u, "GET", "api/incident-graph?id="+c.ID, nil, false); code != 200 || !strings.Contains(string(data), `"incident_version":1`) {
			t.Fatal("graph read", code, string(data))
		}
	}

	if code, _, _ := request(reader, "GET", "api/incidents?id="+c.ID, nil, false); code != 200 {
		t.Fatal("viewer read", code)
	}
	if code, _, _ := request(analyst, "POST", "api/incidents", map[string]any{"action": "comment", "id": c.ID, "version": c.Version, "text": "Investigating", "actor": "root"}, true); code != 400 {
		t.Fatal("forged actor", code)
	}
	code, data, _ = request(analyst, "POST", "api/incidents", map[string]any{"action": "comment", "id": c.ID, "version": c.Version, "text": "Investigating"}, true)
	if code != 200 {
		t.Fatal(code, string(data))
	}
	if code, _, _ := request(analyst, "POST", "api/incidents", map[string]any{"action": "comment", "id": c.ID, "version": c.Version, "text": "Stale"}, true); code != 409 {
		t.Fatal("version guard", code)
	}
	payload["assignee"] = "disabled"
	if code, _, _ := request(analyst, "POST", "api/incidents", payload, true); code != 400 {
		t.Fatal("disabled assignee", code)
	}
	payload["assignee"] = "reader"
	if code, _, _ := request(analyst, "POST", "api/incidents", payload, true); code != 400 {
		t.Fatal("viewer assignee", code)
	}
	if code, data, _ = request(reader, "GET", "api/incidents/history?id="+c.ID, nil, false); code != 200 || !strings.Contains(string(data), "Investigating") {
		t.Fatal("case history", code, string(data))
	}
	if code, _, _ := request(session{}, "GET", "api/investigation?incident="+c.ID, nil, false); code != 401 {
		t.Fatal("unauthenticated investigation", code)
	}
	if code, data, _ := request(reader, "GET", "api/investigation?incident="+c.ID, nil, false); code != 200 || !strings.Contains(string(data), "hypotheses") {
		t.Fatal("investigation read", code, string(data))
	}
	if code, _, _ := request(analyst, "GET", "api/investigation?incident="+c.ID+"&detection="+ds[0].ID, nil, false); code != 400 {
		t.Fatal("ambiguous anchor", code)
	}
	if code, _, _ := request(analyst, "POST", "api/investigation", nil, true); code != 403 && code != 405 {
		t.Fatal("investigation writes allowed", code)
	}
	if code, _, _ := request(reader, "POST", "api/incidents", map[string]any{"action": "link_many", "id": c.ID, "version": c.Version, "detection_ids": []string{ds[0].ID}, "text": "fixture"}, true); code != 403 {
		t.Fatal("viewer bulk write", code)
	}
	if e = control.AdminCommand(ctx, admin.Command{Action: "user.update", Username: "analyst", Role: "analyst", Disabled: true}); e != nil {
		t.Fatal(e)
	}
	if code, _, _ := request(analyst, "GET", "api/incidents", nil, false); code != 401 {
		t.Fatal("disabled analyst session", code)
	}
}
