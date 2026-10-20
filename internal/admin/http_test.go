// SPDX-License-Identifier: Apache-2.0
package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/app"
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAdministratorAuthenticationCSRFAndInventoryPagination(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	asset, err := (app.Service{Repo: store}).AddAsset(ctx, "192.0.2.1", "<img src=x onerror=alert(1)>")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.RegisterAgent(ctx, "agent", asset.ID, strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	p := alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}
	if _, err = store.EvaluateAlerts(ctx, time.Now().Add(2*time.Minute), p); err != nil {
		t.Fatal(err)
	}
	items, _ := store.Alerts(ctx, "active", 0, 10)
	if len(items) != 1 {
		t.Fatal(items)
	}
	snapshot := inventory.Snapshot{SchemaVersion: 1, ID: "snapshot", AssetID: asset.ID, CollectedAt: time.Now().UTC(), Collector: "fixture", Coverage: []inventory.Coverage{{Section: "applications", Status: "partial"}}}
	for i := 0; i < 105; i++ {
		snapshot.Components = append(snapshot.Components, inventory.Component{ID: strings.Repeat("a", i+1), Kind: "application", Name: "<script>bad</script>", Version: "1.0", Source: "fixture"})
	}
	saved, err := (app.InventoryService{Store: store}).Import(ctx, asset.ID, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("a", 64)
	handler, err := admin.NewHandler(store, key, admin.Options{SecureCookies: true, Policy: p})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := server.Client()
	request := func(method, path, body, origin, csrf string, cookie *http.Cookie) (int, []byte, *http.Response) {
		t.Helper()
		r, _ := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if method == "POST" {
			r.Header.Set("Content-Type", "application/json")
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		return response.StatusCode, data, response
	}
	status, body, response := request("GET", "/admin/", "", "", "", nil)
	if status != 200 || bytes.Contains(body, []byte(asset.Name)) || strings.Contains(response.Header.Get("Content-Security-Policy"), "unsafe-inline") {
		t.Fatal(status, string(body))
	}
	for _, path := range []string{"/admin/api/overview", "/admin/api/agents", "/admin/api/alerts", "/admin/api/inventory?id=" + saved.ID} {
		status, _, _ = request("GET", path, "", "", "", nil)
		if status != 401 {
			t.Fatal(path, status)
		}
	}
	payload := `{"token":"` + key + `"}`
	status, _, _ = request("POST", "/admin/login", payload, "https://attacker.invalid", "", nil)
	if status != 403 {
		t.Fatal("cross-origin login", status)
	}
	status, _, response = request("POST", "/admin/login", payload, server.URL, "", nil)
	if status != 200 {
		t.Fatal(status)
	}
	cookies := response.Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal(cookies)
	}
	cookie := cookies[0]
	status, body, _ = request("GET", "/admin/api/session", "", "", "", cookie)
	var session map[string]string
	json.Unmarshal(body, &session)
	csrf := session["csrf"]
	if status != 200 || csrf == "" {
		t.Fatal(status, string(body))
	}
	status, body, _ = request("GET", "/admin/api/agents", "", "", "", cookie)
	if status != 200 || bytes.Contains(body, []byte("token")) || bytes.Contains(body, []byte(asset.Name)) {
		t.Fatal("unsafe JSON or secret exposure", status, string(body))
	}
	for _, attempt := range []struct{ origin, csrf string }{{server.URL, ""}, {"https://attacker.invalid", csrf}} {
		status, _, _ = request("POST", "/admin/api/acknowledge", `{"id":"`+items[0].ID+`"}`, attempt.origin, attempt.csrf, cookie)
		if status != 403 {
			t.Fatal("CSRF bypass", status)
		}
	}
	status, body, _ = request("POST", "/admin/api/acknowledge", `{"id":"`+items[0].ID+`"}`, server.URL, csrf, cookie)
	if status != 200 {
		t.Fatal(status, string(body))
	}
	for _, tc := range []struct{ offset, want int }{{0, 50}, {50, 50}, {100, 5}} {
		path := "/admin/api/inventory?id=" + saved.ID + "&offset=" + jsonNumber(tc.offset)
		status, body, _ = request("GET", path, "", "", "", cookie)
		var v admin.InventoryPage
		if err = json.Unmarshal(body, &v); err != nil || status != 200 || len(v.Items) != tc.want || v.Total != 105 {
			t.Fatal(status, v, err)
		}
	}
	status, _, _ = request("GET", "/admin/api/agents?after=bad%20cursor", "", "", "", cookie)
	if status != 400 {
		t.Fatal(status)
	}
	status, _, _ = request("POST", "/admin/logout", "{}", server.URL, csrf, cookie)
	if status != 200 {
		t.Fatal(status)
	}
	status, _, _ = request("GET", "/admin/api/session", "", "", "", cookie)
	if status != 401 {
		t.Fatal("logout did not revoke session", status)
	}
}
func jsonNumber(n int) string { b, _ := json.Marshal(n); return string(b) }
func TestAgentBearerCannotReadAdministration(t *testing.T) {
	s, err := sqlite.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h, _ := admin.NewHandler(s, strings.Repeat("a", 64), admin.Options{Policy: alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}})
	r := httptest.NewRequest("GET", "http://localhost/admin/api/agents", nil)
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("b", 64))
	r.Header.Set("X-Cerber-Agent", "agent")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
}
