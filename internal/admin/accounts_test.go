// SPDX-License-Identifier: Apache-2.0
package admin_test

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNamedAccountsAndAgentManagement(t *testing.T) {
	ctx := context.Background()
	s, err := sqlite.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	hash, err := admin.HashPassword("fixture-password-123")
	if err != nil {
		t.Fatal(err)
	}
	add := func(name, role string) {
		t.Helper()
		if err := s.AdminCommand(ctx, admin.Command{Action: "user.create", Username: name, Role: role, PasswordHash: hash}); err != nil {
			t.Fatal(err)
		}
	}
	add("root", "administrator")
	add("operator", "operator")
	add("reader", "viewer")
	h, err := admin.NewHandler(s, strings.Repeat("a", 64), admin.Options{Policy: alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h)
	defer server.Close()
	type login struct {
		cookie *http.Cookie
		csrf   string
	}
	request := func(who login, method, path string, body any) (int, []byte, *http.Response) {
		t.Helper()
		data, _ := json.Marshal(body)
		r, _ := http.NewRequest(method, server.URL+"/admin/"+path, strings.NewReader(string(data)))
		r.Header.Set("Origin", server.URL)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", who.csrf)
		if who.cookie != nil {
			r.AddCookie(who.cookie)
		}
		res, e := server.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res.StatusCode, b, res
	}
	signin := func(name string) login {
		t.Helper()
		code, _, r := request(login{}, "POST", "login", map[string]string{"username": name, "password": "fixture-password-123"})
		if code != 200 {
			t.Fatal("login", name, code)
		}
		u := login{cookie: r.Cookies()[0]}
		code, b, _ := request(u, "GET", "api/session", nil)
		var v map[string]string
		json.Unmarshal(b, &v)
		if code != 200 {
			t.Fatal(code)
		}
		u.csrf = v["csrf"]
		return u
	}
	root, operator, viewer := signin("root"), signin("operator"), signin("reader")
	for _, path := range []string{"api/overview", "api/agents", "api/alerts"} {
		if code, _, _ := request(viewer, "GET", path, nil); code != 200 {
			t.Fatal(path, code)
		}
	}
	for _, v := range []struct {
		u    login
		path string
		body any
	}{{viewer, "api/agents/manage", map[string]string{"action": "agent.enroll", "name": "test", "ip": "192.0.2.10"}}, {viewer, "api/acknowledge", map[string]string{"id": "nonexistent"}}, {operator, "api/users", map[string]string{"action": "user.create", "username": "intruder", "role": "administrator", "password": "fixture-password-123"}}} {
		if code, _, _ := request(v.u, "POST", v.path, v.body); code != 403 {
			t.Fatal("forged mutation", v.path, code)
		}
	}
	if code, _, _ := request(operator, "GET", "api/users", nil); code != 403 {
		t.Fatal(code)
	}
	code, b, _ := request(operator, "POST", "api/agents/manage", map[string]string{"action": "agent.enroll", "name": "fixture", "ip": "192.0.2.10"})
	if code != 200 {
		t.Fatal(code, string(b))
	}
	var credentials struct {
		AgentID string `json:"agent_id"`
		Token   string `json:"token"`
		AssetID string `json:"asset_id"`
	}
	json.Unmarshal(b, &credentials)
	if credentials.Token == "" || credentials.AssetID == "" {
		t.Fatal("missing credentials")
	}
	if _, err = s.AgentBinding(ctx, credentials.AgentID, ingest.Hash([]byte(credentials.Token))); err != nil {
		t.Fatal(err)
	}
	if code, b, _ = request(viewer, "GET", "api/agents", nil); code != 200 || strings.Contains(string(b), credentials.Token) || strings.Contains(string(b), "token_hash") {
		t.Fatal("secret exposed", code)
	}
	if _, err = s.EvaluateAlerts(ctx, time.Now().Add(2*time.Minute), alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}); err != nil {
		t.Fatal(err)
	}
	active, err := s.Alerts(ctx, "active", 0, 10)
	if err != nil || len(active) != 1 {
		t.Fatal(active, err)
	}
	if code, b, _ = request(operator, "POST", "api/acknowledge", map[string]string{"id": active[0].ID}); code != 200 || !strings.Contains(string(b), `"acknowledged_by":"operator"`) {
		t.Fatal("named acknowledgement", code, string(b))
	}
	if code, _, _ = request(operator, "POST", "api/agents/manage", map[string]string{"action": "agent.revoke", "agent_id": credentials.AgentID}); code != 200 {
		t.Fatal(code)
	}
	if _, err = s.AgentBinding(ctx, credentials.AgentID, ingest.Hash([]byte(credentials.Token))); !errors.Is(err, ingest.ErrUnauthorized) {
		t.Fatal(err)
	}
	if code, b, _ = request(root, "GET", "api/users", nil); code != 200 || strings.Contains(string(b), hash) || strings.Contains(string(b), "password_hash") {
		t.Fatal("password hash exposed", code)
	}
	if code, _, _ = request(root, "POST", "api/users", map[string]any{"action": "user.update", "username": "root", "role": "viewer"}); code != 409 {
		t.Fatal("last administrator", code)
	}
	// A role change revokes every session and stale write principal, even before cookie expiry.
	stale, _ := s.AdminUser(ctx, "operator")
	if code, _, _ = request(root, "POST", "api/users", map[string]any{"action": "user.update", "username": "operator", "role": "viewer"}); code != 200 {
		t.Fatal(code)
	}
	if code, _, _ = request(operator, "GET", "api/agents", nil); code != 401 {
		t.Fatal("stale session", code)
	}
	if err = s.AdminCommand(admin.WithPrincipal(ctx, stale), admin.Command{Action: "agent.revoke", AgentID: credentials.AgentID}); !errors.Is(err, admin.ErrForbidden) {
		t.Fatal("stale transaction", err)
	}
	if code, _, _ = request(root, "POST", "api/users", map[string]any{"action": "user.update", "username": "reader", "role": "viewer", "disabled": true}); code != 200 {
		t.Fatal(code)
	}
	if code, _, _ = request(viewer, "GET", "api/session", nil); code != 401 {
		t.Fatal("disabled session", code)
	}
	if code, _, _ = request(login{}, "POST", "login", map[string]string{"username": "reader", "password": "fixture-password-123"}); code != 401 {
		t.Fatal("disabled login", code)
	}
	if code, _, _ = request(login{}, "POST", "login", map[string]string{"token": strings.Repeat("a", 64)}); code != 401 {
		t.Fatal("legacy bypass", code)
	}
	renewed := signin("operator")
	if code, _, _ = request(root, "POST", "api/users", map[string]any{"action": "user.update", "username": "operator", "role": "viewer", "password": "changed-fixture-password-456"}); code != 200 {
		t.Fatal("password reset", code)
	}
	if code, _, _ = request(renewed, "GET", "api/session", nil); code != 401 {
		t.Fatal("password reset session", code)
	}
	if code, _, _ = request(login{}, "POST", "login", map[string]string{"username": "operator", "password": "fixture-password-123"}); code != 401 {
		t.Fatal("old password", code)
	}
	if code, _, _ = request(login{}, "POST", "login", map[string]string{"username": "operator", "password": "changed-fixture-password-456"}); code != 200 {
		t.Fatal("new password", code)
	}
	events, err := s.Events(ctx, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(events)
	for _, secret := range []string{hash, "fixture-password-123", "changed-fixture-password-456", credentials.Token} {
		if strings.Contains(string(data), secret) {
			t.Fatal("audit leaked secret")
		}
	}
	if !strings.Contains(string(data), `"actor":"operator"`) {
		t.Fatal("missing audit actor")
	}
	// Named accounts are durable across a new handler; sessions are not.
	h2, _ := admin.NewHandler(s, "", admin.Options{Policy: alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/admin/api/session", nil)
	r.AddCookie(root.cookie)
	h2.ServeHTTP(rec, r)
	if rec.Code != 401 {
		t.Fatal("old handler cookie", rec.Code)
	}
	if err = s.AdminCommand(ctx, admin.Command{Action: "user.create", Username: "root", Role: "administrator", PasswordHash: hash}); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("duplicate", err)
	}
}
func TestPasswords(t *testing.T) {
	if _, err := admin.HashPassword("short"); err == nil {
		t.Fatal("short password")
	}
	a, _ := admin.HashPassword("fixture-password-123")
	b, _ := admin.HashPassword("fixture-password-123")
	if a == b || !admin.CheckPassword(a, "fixture-password-123") || admin.CheckPassword(a, "wrong") {
		t.Fatal("password derivation")
	}
	if admin.CheckPassword("corrupt", "fixture-password-123") {
		t.Fatal("invalid hash")
	}
}

func TestLegacyBootstrapClosesAfterFirstNamedAdministrator(t *testing.T) {
	ctx := context.Background()
	s, err := sqlite.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	key := strings.Repeat("b", 64)
	h, err := admin.NewHandler(s, key, admin.Options{Policy: alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "http://localhost/admin/"+path, strings.NewReader(body))
		r.Header.Set("Origin", "http://localhost")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	rec := request("POST", "login", `{"token":"`+key+`"}`, "", nil)
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	cookie := rec.Result().Cookies()[0]
	rec = request("GET", "api/session", "", "", cookie)
	var session map[string]string
	json.Unmarshal(rec.Body.Bytes(), &session)
	rec = request("POST", "api/users", `{"action":"user.create","username":"first-admin","role":"administrator","password":"bootstrap-fixture-password"}`, session["csrf"], cookie)
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	rec = request("GET", "api/session", "", "", cookie)
	if rec.Code != 401 {
		t.Fatal("legacy session survived", rec.Code)
	}
	rec = request("POST", "login", `{"token":"`+key+`"}`, "", nil)
	if rec.Code != 401 {
		t.Fatal("legacy login survived", rec.Code)
	}
	rec = request("POST", "login", `{"username":"first-admin","password":"bootstrap-fixture-password"}`, "", nil)
	if rec.Code != 200 {
		t.Fatal("named bootstrap login", rec.Code)
	}
}
