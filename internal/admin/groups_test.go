// SPDX-License-Identifier: Apache-2.0
package admin_test

import (
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/app"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/jobs"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGroupAPIRequiresRoleCSRFAndCurrentScope(t *testing.T) {
	ctx := context.Background()
	s, e := sqlite.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	hash, _ := admin.HashPassword("fixture-long-password")
	for _, u := range []admin.User{{Username: "root", Role: "administrator"}, {Username: "operator", Role: "operator"}, {Username: "reader", Role: "viewer"}} {
		if e = s.AdminCommand(ctx, admin.Command{Action: "user.create", Username: u.Username, Role: u.Role, PasswordHash: hash}); e != nil {
			t.Fatal(e)
		}
	}
	asset, e := (app.Service{Repo: s}).AddAsset(ctx, "192.0.2.21", "fixture")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.RegisterAgent(ctx, "agent", asset.ID, ingest.Hash([]byte(strings.Repeat("a", 64)))); e != nil {
		t.Fatal(e)
	}
	h, e := admin.NewHandler(s, "", admin.Options{Policy: alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(h)
	defer server.Close()
	type session struct {
		cookie *http.Cookie
		csrf   string
	}
	request := func(u session, method, path, origin string, v any) (int, []byte, *http.Response) {
		t.Helper()
		data, _ := json.Marshal(v)
		r, _ := http.NewRequest(method, server.URL+"/admin/"+path, strings.NewReader(string(data)))
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", u.csrf)
		if u.cookie != nil {
			r.AddCookie(u.cookie)
		}
		res, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res.StatusCode, b, res
	}
	login := func(name string) session {
		code, _, r := request(session{}, "POST", "login", server.URL, map[string]string{"username": name, "password": "fixture-long-password"})
		if code != 200 {
			t.Fatal(code)
		}
		u := session{cookie: r.Cookies()[0]}
		_, b, _ := request(u, "GET", "api/session", "", nil)
		var v map[string]string
		json.Unmarshal(b, &v)
		u.csrf = v["csrf"]
		return u
	}
	op, reader := login("operator"), login("reader")
	create := map[string]any{"action": "create", "name": "<script>fixture</script>", "description": "Fixture group"}
	for _, path := range []string{"api/groups", "api/groups/members", "api/group-runs", "api/group-schedules"} {
		if code, _, _ := request(reader, "POST", path, server.URL, create); code != 403 {
			t.Fatal("viewer write", path, code)
		}
	}
	if code, _, _ := request(session{cookie: op.cookie}, "POST", "api/groups", server.URL, create); code != 403 {
		t.Fatal("missing CSRF", code)
	}
	if code, _, _ := request(op, "POST", "api/groups", "http://attacker.invalid", create); code != 403 {
		t.Fatal("origin", code)
	}
	code, b, _ := request(op, "POST", "api/groups", server.URL, create)
	if code != 200 {
		t.Fatal(code, string(b))
	}
	var result map[string]string
	json.Unmarshal(b, &result)
	id := result["id"]
	if code, b, _ = request(reader, "GET", "api/groups?id="+id, "", nil); code != 200 || strings.Contains(string(b), "<script>") {
		t.Fatal("group disclosure/XSS escaping", code, string(b))
	}
	if code, b, _ = request(op, "POST", "api/groups/members", server.URL, map[string]any{"action": "members.add", "group_id": id, "group_version": 1, "agent_ids": []string{"agent", "agent"}}); code != 200 {
		t.Fatal(code, string(b))
	}
	if code, _, _ = request(op, "POST", "api/group-runs", server.URL, map[string]any{"action": "run", "group_id": id, "group_version": 1, "kind": "inventory"}); code != 409 {
		t.Fatal("stale target scope", code)
	}
	if code, b, _ = request(reader, "GET", "api/groups/members?group="+id, "", nil); code != 200 {
		t.Fatal(code)
	}
	var members struct {
		Group jobs.Group         `json:"group"`
		Items []jobs.GroupMember `json:"items"`
	}
	json.Unmarshal(b, &members)
	if members.Group.Members != 1 || len(members.Items) != 1 {
		t.Fatal(members)
	}
	command := map[string]any{"action": "run", "group_id": id, "group_version": members.Group.Version, "kind": "updates"}
	if code, _, _ = request(op, "POST", "api/groups", server.URL, command); code != 400 {
		t.Fatal("action routing", code)
	}
	if code, b, _ = request(op, "POST", "api/group-runs", server.URL, command); code != 200 {
		t.Fatal(code, string(b))
	}
	json.Unmarshal(b, &result)
	run := result["id"]
	if code, b, _ = request(reader, "GET", "api/group-run-members?run="+run, "", nil); code != 200 || !strings.Contains(string(b), `"state":"queued"`) {
		t.Fatal(code, string(b))
	}
	schedule := map[string]any{"action": "schedule.create", "group_id": id, "group_version": members.Group.Version, "kind": "inventory", "interval_seconds": 60, "first_run_at": time.Now().Add(time.Minute)}
	if code, b, _ = request(op, "POST", "api/group-schedules", server.URL, schedule); code != 200 {
		t.Fatal(code, string(b))
	}
	if code, _, _ = request(reader, "GET", "api/group-schedules?group="+id, "", nil); code != 200 {
		t.Fatal(code)
	}
	if code, _, _ = request(reader, "GET", "api/group-runs?before=-1", "", nil); code != 400 {
		t.Fatal("cursor", code)
	}
	if code, b, res := request(session{}, "GET", "groups.js", "", nil); code != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "application/javascript") || len(b) == 0 {
		t.Fatal("embedded module", code)
	}
}
