// SPDX-License-Identifier: Apache-2.0
package admin_test

import (
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/app"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestJobAPIEnforcesRolesOriginAndCSRF(t *testing.T) {
	ctx := context.Background()
	s, err := sqlite.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	hash, _ := admin.HashPassword("fixture-long-password")
	for _, u := range []admin.User{{Username: "root", Role: "administrator"}, {Username: "operator", Role: "operator"}, {Username: "reader", Role: "viewer"}} {
		if err = s.AdminCommand(ctx, admin.Command{Action: "user.create", Username: u.Username, Role: u.Role, PasswordHash: hash}); err != nil {
			t.Fatal(err)
		}
	}
	asset, err := (app.Service{Repo: s}).AddAsset(ctx, "192.0.2.20", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RegisterAgent(ctx, "agent", asset.ID, ingest.Hash([]byte(strings.Repeat("a", 64)))); err != nil {
		t.Fatal(err)
	}
	handler, _ := admin.NewHandler(s, "", admin.Options{Policy: alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}})
	server := httptest.NewServer(handler)
	defer server.Close()
	type session struct {
		cookie *http.Cookie
		csrf   string
	}
	req := func(u session, method, path, origin string, body any) (int, []byte, *http.Response) {
		t.Helper()
		data, _ := json.Marshal(body)
		r, _ := http.NewRequest(method, server.URL+"/admin/"+path, strings.NewReader(string(data)))
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", u.csrf)
		if u.cookie != nil {
			r.AddCookie(u.cookie)
		}
		res, e := server.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res.StatusCode, b, res
	}
	login := func(name string) session {
		t.Helper()
		code, _, r := req(session{}, "POST", "login", server.URL, map[string]string{"username": name, "password": "fixture-long-password"})
		if code != 200 {
			t.Fatal(code)
		}
		u := session{cookie: r.Cookies()[0]}
		_, b, _ := req(u, "GET", "api/session", "", nil)
		var v map[string]string
		json.Unmarshal(b, &v)
		u.csrf = v["csrf"]
		return u
	}
	operator, reader := login("operator"), login("reader")
	command := map[string]any{"action": "run", "agent_id": "agent", "kind": "inventory"}
	for _, path := range []string{"api/jobs", "api/schedules"} {
		if code, _, _ := req(reader, "GET", path, "", nil); code != 200 {
			t.Fatal("viewer read", code)
		}
		if code, _, _ := req(reader, "POST", path, server.URL, command); code != 403 {
			t.Fatal("viewer write", code)
		}
	}
	if code, _, _ := req(session{cookie: operator.cookie}, "POST", "api/jobs", server.URL, command); code != 403 {
		t.Fatal("CSRF", code)
	}
	if code, _, _ := req(operator, "POST", "api/jobs", "http://attacker.invalid", command); code != 403 {
		t.Fatal("origin", code)
	}
	if code, _, _ := req(operator, "POST", "api/jobs", server.URL, map[string]string{"action": "run", "agent_id": "agent", "kind": "shell"}); code != 400 {
		t.Fatal("arbitrary execution", code)
	}
	code, data, _ := req(operator, "POST", "api/jobs", server.URL, command)
	if code != 200 {
		t.Fatal(code, string(data))
	}
	var created map[string]string
	json.Unmarshal(data, &created)
	if code, data, _ = req(reader, "GET", "api/jobs?agent=agent", "", nil); code != 200 || !strings.Contains(string(data), created["id"]) {
		t.Fatal("missing status", code, string(data))
	}
	schedule := map[string]any{"action": "schedule.create", "agent_id": "agent", "kind": "updates", "interval_seconds": 3600, "first_run_at": time.Now().Add(time.Minute).Format(time.RFC3339Nano)}
	if code, data, _ = req(operator, "POST", "api/schedules", server.URL, schedule); code != 200 {
		t.Fatal(code, string(data))
	}
	json.Unmarshal(data, &created)
	if code, _, _ = req(operator, "POST", "api/schedules", server.URL, map[string]string{"action": "schedule.disable", "id": created["id"]}); code != 200 {
		t.Fatal(code)
	}
	if code, data, _ = req(reader, "GET", "api/schedules?agent=agent", "", nil); code != 200 || !strings.Contains(string(data), `"enabled":false`) {
		t.Fatal("schedule pause", code, string(data))
	}
	if code, _, _ = req(reader, "GET", "api/jobs?before=-1", "", nil); code != 400 {
		t.Fatal("cursor", code)
	}
}
