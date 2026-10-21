// SPDX-License-Identifier: Apache-2.0
package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPatchHTTPRequiresNamedAdministratorAndCSRF(t *testing.T) {
	ctx := context.Background()
	s, e := sqlite.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	hash, _ := admin.HashPassword("patch-fixture-password")
	for _, role := range []string{"administrator", "operator", "analyst", "viewer"} {
		if e = s.AdminCommand(ctx, admin.Command{Action: "user.create", Username: role, Role: role, PasswordHash: hash}); e != nil {
			t.Fatal(e)
		}
	}
	h, e := admin.NewHandler(s, "", admin.Options{PatchEnabled: true, Policy: alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(h)
	defer server.Close()
	call := func(path string, body any, cookie *http.Cookie, csrf string) (int, []byte, *http.Response) {
		b, _ := json.Marshal(body)
		method := "POST"
		if body == nil {
			method = "GET"
		}
		r, _ := http.NewRequest(method, server.URL+"/admin/"+path, bytes.NewReader(b))
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
	for _, role := range []string{"administrator", "operator", "analyst", "viewer"} {
		code, _, res := call("login", map[string]string{"username": role, "password": "patch-fixture-password"}, nil, "")
		if code != 200 {
			t.Fatal(code)
		}
		cookie := res.Cookies()[0]
		_, b, _ := call("api/session", nil, cookie, "")
		var session map[string]string
		json.Unmarshal(b, &session)
		if code, _, _ = call("api/patches", nil, cookie, ""); code != 200 {
			t.Fatal(role, "read", code)
		}
		if code, _, _ = call("api/patches", map[string]string{"action": "preview"}, cookie, ""); code != 403 {
			t.Fatal(role, "missing csrf", code)
		}
		code, _, _ = call("api/patches", map[string]string{"action": "preview"}, cookie, session["csrf"])
		want := 403
		if role == "administrator" {
			want = 400
		}
		if code != want {
			t.Fatal(role, code, want)
		}
	}
}
