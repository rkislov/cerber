// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"github.com/rkislov/cerber/internal/telemetry"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestSearchAndRetentionHTTPPermissionsDownloadsAndExpiry(t *testing.T) {
	ctx := context.Background()
	events, _, batch := oldJournal(t)
	if e := events.SamplePipelineHealth(ctx, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	control, e := sqlite.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer control.Close()
	hash, _ := admin.HashPassword("retention-fixture-password")
	for _, role := range []string{"administrator", "operator", "analyst", "viewer"} {
		if e = control.AdminCommand(ctx, admin.Command{Action: "user.create", Username: role, Role: role, PasswordHash: hash}); e != nil {
			t.Fatal(e)
		}
	}
	handler, e := admin.NewHandler(control, "", admin.Options{Events: events, Policy: alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	call := func(method, path string, body any, cookie *http.Cookie, csrf string) (int, []byte, *http.Response) {
		t.Helper()
		data, _ := json.Marshal(body)
		r, _ := http.NewRequest(method, server.URL+"/admin/"+path, bytes.NewReader(data))
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
		data, _ = io.ReadAll(res.Body)
		res.Body.Close()
		return res.StatusCode, data, res
	}
	if code, _, _ := call("GET", "api/security-events", nil, nil, ""); code != 401 {
		t.Fatal("anonymous search", code)
	}
	if code, _, _ := call("GET", "api/event-health", nil, nil, ""); code != 401 {
		t.Fatal("anonymous health", code)
	}
	var root, viewer *http.Cookie
	var rootCSRF string
	policy := map[string]any{"action": "configure", "confirm": true, "policy": telemetry.RetentionPolicy{Enabled: true, HotDays: 1, ArchiveDays: 2, Version: 2}}
	for _, role := range []string{"administrator", "operator", "analyst", "viewer"} {
		code, _, res := call("POST", "login", map[string]string{"username": role, "password": "retention-fixture-password"}, nil, "")
		if code != 200 {
			t.Fatal(code)
		}
		cookie := res.Cookies()[0]
		_, b, _ := call("GET", "api/session", nil, cookie, "")
		var session map[string]string
		json.Unmarshal(b, &session)
		csrf := session["csrf"]
		code, b, _ = call("GET", "api/security-events?q="+url.QueryEscape("ОШИБКА ПОДКЛЮЧЕНИЯ")+"&source=journald", nil, cookie, "")
		var result struct{ Items []telemetry.Normalized }
		json.Unmarshal(b, &result)
		if code != 200 || len(result.Items) != 2 {
			t.Fatal(role, "search", code, string(b))
		}
		if code, _, _ = call("GET", "api/event-health", nil, cookie, ""); code != 200 {
			t.Fatal(role, "health", code)
		}
		if code, _, _ = call("GET", "api/event-retention", nil, cookie, ""); code != 200 {
			t.Fatal(role, "read policy", code)
		}
		if code, _, _ = call("POST", "api/event-retention", policy, cookie, ""); code != 403 {
			t.Fatal(role, "missing csrf", code)
		}
		if role != "administrator" {
			if code, _, _ = call("POST", "api/event-retention", policy, cookie, csrf); code != 403 {
				t.Fatal(role, "policy mutation", code)
			}
			if code, _, _ = call("POST", "api/event-retention", map[string]string{"action": "run"}, cookie, csrf); code != 403 {
				t.Fatal(role, "manual cleanup", code)
			}
		} else {
			root, rootCSRF = cookie, csrf
		}
		if role == "viewer" {
			viewer = cookie
		}
	}
	if code, _, _ := call("POST", "api/event-retention", policy, root, rootCSRF); code != 200 {
		t.Fatal("save policy", code)
	}
	if code, _, _ := call("POST", "api/event-retention", policy, root, rootCSRF); code != 409 {
		t.Fatal("stale policy", code)
	}
	if code, _, _ := call("POST", "api/event-retention", map[string]any{"action": "configure", "policy": telemetry.RetentionPolicy{Enabled: true, HotDays: 1, ArchiveDays: 2, Version: 3}}, root, rootCSRF); code != 400 {
		t.Fatal("missing explicit confirmation", code)
	}
	if code, _, _ := call("POST", "api/event-retention", map[string]string{"action": "configure", "archive_dir": "/untrusted"}, root, rootCSRF); code != 400 {
		t.Fatal("browser selected filesystem path", code)
	}
	code, b, _ := call("POST", "api/event-retention", map[string]string{"action": "run"}, root, rootCSRF)
	if code != 200 {
		t.Fatal(code, string(b))
	}
	var run struct{ Archived int }
	json.Unmarshal(b, &run)
	if run.Archived != 2 {
		t.Fatal(run)
	}
	code, b, _ = call("GET", "api/event-archives", nil, viewer, "")
	var list struct{ Items []telemetry.Archive }
	json.Unmarshal(b, &list)
	if code != 200 || len(list.Items) != 1 {
		t.Fatal(code, string(b))
	}
	id := list.Items[0].ID
	verifyCode, verifyBody, _ := call("GET", "api/event-archives?id="+id+"&verify=1", nil, viewer, "")
	var check telemetry.ArchiveCheck
	json.Unmarshal(verifyBody, &check)
	if verifyCode != 200 || !check.Verified || len(check.EventIDs) != 2 {
		t.Fatal("verified recovery API", verifyCode, string(verifyBody))
	}
	code, b, res := call("GET", "api/event-archives?id="+id, nil, viewer, "")
	sum := sha256.Sum256(b)
	if code != 200 || res.Header.Get("Content-Type") != "application/gzip" || res.Header.Get("X-Archive-SHA256") != hex.EncodeToString(sum[:]) {
		t.Fatal("unverified archive download", code)
	}
	rawID := telemetry.ID(batch.AgentID, batch.Records[0].ID)
	code, b, _ = call("GET", "api/security-raw?id="+rawID, nil, viewer, "")
	var raw struct{ Archived bool }
	json.Unmarshal(b, &raw)
	if code != 200 || !raw.Archived {
		t.Fatal("archived original", code, string(b))
	}
	if code, _, _ = call("GET", "api/event-archives?id=..%2F..%2Fprivate", nil, viewer, ""); code != 400 {
		t.Fatal("path traversal", code)
	}
	if _, e = events.Maintain(ctx, time.Now().Add(4*24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	if code, _, _ = call("GET", "api/security-raw?id="+rawID, nil, viewer, ""); code != 410 {
		t.Fatal("expired evidence response", code)
	}
	if code, _, _ = call("GET", "api/event-archives?id="+id, nil, viewer, ""); code != 410 {
		t.Fatal("expired archive response", code)
	}
	history, _ := events.RetentionHistory(ctx, 0)
	found := false
	for _, a := range history {
		if a.Actor == "administrator" && a.Action == "maintenance.requested" {
			found = true
		}
	}
	if !found {
		t.Fatal("manual requester missing from audit")
	}
}
