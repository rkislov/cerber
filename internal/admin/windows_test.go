// SPDX-License-Identifier: Apache-2.0
package admin_test

import (
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/app"
	"github.com/rkislov/cerber/internal/endpoint"
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"github.com/rkislov/cerber/internal/vuln"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWindowsReportAuthenticationAndSyncAuthorization(t *testing.T) {
	ctx := context.Background()
	s, e := sqlite.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c, e := vuln.Open(filepath.Join(t.TempDir(), "catalog.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	asset, e := (app.Service{Repo: s}).AddAsset(ctx, "192.0.2.10", "Windows fixture")
	if e != nil {
		t.Fatal(e)
	}
	snap := inventory.Snapshot{SchemaVersion: 1, ID: "windows", AssetID: asset.ID, CollectedAt: time.Now(), Collector: "fixture", OS: inventory.OS{Family: "windows"}, Coverage: []inventory.Coverage{{Section: "os", Status: "partial"}}}
	saved, e := (app.InventoryService{Store: s}).Import(ctx, asset.ID, snap)
	if e != nil {
		t.Fatal(e)
	}
	hash, _ := admin.HashPassword("fixture-windows-password")
	if e = s.AdminCommand(ctx, admin.Command{Action: "user.create", Username: "fixture", Role: "administrator", PasswordHash: hash}); e != nil {
		t.Fatal(e)
	}
	handler, e := admin.NewHandler(s, "", admin.Options{Endpoint: &endpoint.Server{Catalog: c}, Policy: alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	call := func(method, path, body, csrf string) (int, []byte) {
		t.Helper()
		r, _ := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if method == "POST" {
			r.Header.Set("Origin", server.URL)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", csrf)
		}
		resp, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, data
	}
	if code, _ := call("GET", "/admin/api/windows-vulnerabilities?id="+saved.ID, "", ""); code != 401 {
		t.Fatal(code)
	}
	if code, data := call("GET", "/admin/windows.js", "", ""); code != 200 || !strings.Contains(string(data), "loadWindowsVulnerabilities") {
		t.Fatal(code)
	}
	if code, _ := call("POST", "/admin/login", `{"username":"fixture","password":"fixture-windows-password"}`, ""); code != 200 {
		t.Fatal(code)
	}
	_, data := call("GET", "/admin/api/session", "", "")
	var session struct {
		CSRF string `json:"csrf"`
	}
	json.Unmarshal(data, &session)
	if code, data := call("GET", "/admin/api/inventory?id="+saved.ID, "", ""); code != 200 || !strings.Contains(string(data), `"items":[]`) {
		t.Fatal("empty inventory", code, string(data))
	}
	if code, data := call("GET", "/admin/api/windows-vulnerabilities?id="+saved.ID, "", ""); code != 200 || !strings.Contains(string(data), `"status":"unknown"`) {
		t.Fatal(code, string(data))
	}
	if code, _ := call("GET", "/admin/api/windows-vulnerabilities?id=missing", "", ""); code != 404 {
		t.Fatal(code)
	}
	if code, _ := call("GET", "/admin/api/windows-vulnerabilities?id="+saved.ID+"&offset=-1", "", ""); code != 400 {
		t.Fatal(code)
	}
	if code, _ := call("POST", "/admin/api/microsoft-catalog", `{"action":"refresh"}`, ""); code != 403 {
		t.Fatal(code)
	}
	if code, _ := call("POST", "/admin/api/microsoft-catalog", `{"action":"refresh"}`, session.CSRF); code != 200 {
		t.Fatal(code)
	}
}
