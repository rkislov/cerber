// SPDX-License-Identifier: Apache-2.0
package admin_test

import (
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/eventstore"
	"github.com/rkislov/cerber/internal/rulepolicy"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"github.com/rkislov/cerber/internal/telemetry"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCorrelationPolicyAPIReadRolesCSRFAndConflict(t *testing.T) {
	ctx := context.Background()
	control, e := sqlite.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer control.Close()
	events, e := eventstore.Open(ctx, filepath.Join(t.TempDir(), "events.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer events.Close()
	events.SetRuleGroupSource(control)
	hash, _ := admin.HashPassword("rule-policy-fixture-password")
	for _, u := range []struct{ name, role string }{{"owner", "administrator"}, {"analyst", "analyst"}, {"reader", "viewer"}} {
		if e = control.AdminCommand(ctx, admin.Command{Action: "user.create", Username: u.name, Role: u.role, PasswordHash: hash}); e != nil {
			t.Fatal(e)
		}
	}
	now := time.Now().UTC()
	p, _ := json.Marshal(map[string]any{"event_id": 1102, "time": now.Format(time.RFC3339Nano), "provider": "Microsoft-Windows-Eventlog", "fields": map[string]string{"SubjectUserName": "Alice", "SubjectDomainName": "LAB"}})
	rawID := telemetry.ID("audit")
	b := telemetry.Batch{SchemaVersion: 1, ID: telemetry.ID("batch"), AgentID: "agent", Records: []telemetry.Raw{{ID: rawID, Source: "windows:Security", Cursor: "1", ObservedAt: now, Data: p}}}
	events.Accept(ctx, "agent", "asset", b)
	if e = events.Step(ctx); e != nil {
		t.Fatal(e)
	}
	handler, e := admin.NewHandler(control, "", admin.Options{Events: events, Policy: alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	type session struct {
		client *http.Client
		csrf   string
	}
	call := func(s session, method, path string, body any, csrf bool) (int, []byte) {
		t.Helper()
		data, _ := json.Marshal(body)
		r, _ := http.NewRequest(method, server.URL+"/admin/"+path, strings.NewReader(string(data)))
		if method == "POST" {
			r.Header.Set("Origin", server.URL)
			r.Header.Set("Content-Type", "application/json")
			if csrf {
				r.Header.Set("X-CSRF-Token", s.csrf)
			}
		}
		resp, e := s.client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		data, _ = io.ReadAll(resp.Body)
		return resp.StatusCode, data
	}
	login := func(name string) session {
		t.Helper()
		jar, _ := cookiejar.New(nil)
		s := session{client: &http.Client{Jar: jar}}
		if code, _ := call(s, "POST", "login", map[string]string{"username": name, "password": "rule-policy-fixture-password"}, false); code != 200 {
			t.Fatal(code)
		}
		_, p := call(s, "GET", "api/session", nil, false)
		var v map[string]string
		json.Unmarshal(p, &v)
		s.csrf = v["csrf"]
		return s
	}
	owner, analyst, reader := login("owner"), login("analyst"), login("reader")
	cfg := rulepolicy.Defaults()["windows.audit_log_cleared"]
	cfg.Enabled = false
	change := rulepolicy.Change{Action: "save", Rule: "windows.audit_log_cleared", ExpectedRevision: 1, Config: cfg, Reason: "Fixture disable"}
	for _, u := range []session{analyst, reader} {
		if code, _ := call(u, "POST", "api/rule-policies", change, true); code != 403 {
			t.Fatal("non-admin activation", code)
		}
	}
	if code, _ := call(owner, "POST", "api/rule-policies", change, false); code != 403 {
		t.Fatal("missing CSRF", code)
	}
	if code, p := call(owner, "POST", "api/rule-policies", change, true); code != 200 {
		t.Fatal(code, string(p))
	}
	if code, _ := call(owner, "POST", "api/rule-policies", change, true); code != 409 {
		t.Fatal("stale policy write", code)
	}
	if code, p := call(reader, "GET", "api/rule-policies/history?id=windows.audit_log_cleared", nil, false); code != 200 || !strings.Contains(string(p), "Fixture disable") {
		t.Fatal(code, string(p))
	}
	draft := map[string]any{"rule": "windows.audit_log_cleared", "config": rulepolicy.Defaults()["windows.audit_log_cleared"], "event_ids": []string{telemetry.ID("agent", rawID)}}
	before, _ := events.ReadDetections(ctx, 0, 100)
	if code, _ := call(reader, "POST", "api/rule-policies/preview", draft, true); code != 403 {
		t.Fatal(code)
	}
	if code, p := call(analyst, "POST", "api/rule-policies/preview", draft, true); code != 200 || !strings.Contains(string(p), `"dry_run":true`) {
		t.Fatal(code, string(p))
	}
	after, _ := events.ReadDetections(ctx, 0, 100)
	if len(before) != len(after) {
		t.Fatal("preview created production finding")
	}
	change.Config.GroupIDs = []string{strings.Repeat("a", 32)}
	change.ExpectedRevision = 2
	if code, _ := call(owner, "POST", "api/rule-policies", change, true); code != 400 {
		t.Fatal("unknown group accepted", code)
	}
	rollback := rulepolicy.Change{Action: "rollback", Rule: change.Rule, ExpectedRevision: 2, TargetRevision: 1, Reason: "Restore"}
	if code, p := call(owner, "POST", "api/rule-policies", rollback, true); code != 200 || !strings.Contains(string(p), `"restored_from":1`) {
		t.Fatal(code, string(p))
	}
}
