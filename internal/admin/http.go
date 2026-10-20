// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/ingest"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

//go:embed static/*
var content embed.FS

type Options struct {
	SecureCookies bool
	Policy        alerts.Policy
	Monitor       func() alerts.Status
}

func NewHandler(store Store, key string, options Options) (http.Handler, error) {
	if key != "" && !ValidKey(key) {
		return nil, errors.New("administrator key must be 32 random bytes encoded as hex")
	}
	if err := options.Policy.Validate(); err != nil {
		return nil, err
	}
	auth := newAuth(key, options.SecureCookies, store)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'")
		path := r.URL.Path
		if r.Method == "GET" && (path == "/admin" || path == "/admin/" || path == "/admin/app.js" || path == "/admin/app.css" || path == "/admin/icon.svg") {
			name := "index.html"
			if path == "/admin/icon.svg" {
				name = "icon.svg"
				w.Header().Set("Content-Type", "image/svg+xml")
			}
			if path == "/admin/app.js" {
				name = "app.js"
				w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
			} else if path == "/admin/app.css" {
				name = "app.css"
				w.Header().Set("Content-Type", "text/css; charset=utf-8")
			} else if path != "/admin/icon.svg" {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
			}
			data, _ := content.ReadFile("static/" + name)
			_, _ = w.Write(data)
			return
		}
		if !strings.HasPrefix(path, "/admin/") {
			http.NotFound(w, r)
			return
		}
		if r.Method != "GET" && r.Method != "POST" {
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", 405)
			return
		}
		if r.Method == "POST" {
			scheme := "http"
			if options.SecureCookies || r.TLS != nil {
				scheme = "https"
			}
			origin, err := url.Parse(r.Header.Get("Origin"))
			if err != nil || origin.Scheme != scheme || origin.Host != r.Host || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.User != nil {
				http.Error(w, "same-origin request required", 403)
				return
			}
			media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || media != "application/json" {
				http.Error(w, "JSON required", 415)
				return
			}
		}
		if path == "/admin/login" && r.Method == "POST" {
			auth.login(w, r)
			return
		}
		session, ok := auth.current(r)
		if !ok {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.Method == "POST" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(session.CSRF)) != 1 {
			http.Error(w, "CSRF validation failed", 403)
			return
		}
		if path == "/admin/logout" && r.Method == "POST" {
			auth.logout(w, r)
			return
		}
		if path == "/admin/api/session" && r.Method == "GET" {
			writeJSON(w, map[string]string{"csrf": session.CSRF, "role": session.User.Role, "username": session.User.Username})
			return
		}
		r = r.WithContext(WithPrincipal(r.Context(), session.User))
		if r.Method == "POST" && session.User.Role == "viewer" {
			http.Error(w, "forbidden", 403)
			return
		}
		if strings.HasPrefix(path, "/admin/api/users") && session.User.Role != "administrator" {
			http.Error(w, "forbidden", 403)
			return
		}
		if management(store, w, r) {
			return
		}
		switch path {
		case "/admin/api/overview":
			if r.Method != "GET" {
				break
			}
			now := time.Now().UTC()
			v, err := store.AdminOverview(r.Context(), now, options.Policy)
			if err != nil {
				storageError(w, err)
				return
			}
			monitor := alerts.Status{}
			if options.Monitor != nil {
				monitor = options.Monitor()
			}
			writeJSON(w, map[string]any{"as_of": now, "summary": v, "monitor": monitor})
			return
		case "/admin/api/agents":
			if r.Method != "GET" {
				break
			}
			limit, err := integer(r, "limit", 100, 1, 1000)
			if err != nil {
				http.Error(w, "invalid limit", 400)
				return
			}
			after := r.URL.Query().Get("after")
			if after != "" && !ingest.Identifier(after) {
				http.Error(w, "invalid cursor", 400)
				return
			}
			items, err := store.AgentStatuses(r.Context(), "", after, limit+1)
			if err != nil {
				storageError(w, err)
				return
			}
			next := ""
			if len(items) > limit {
				items = items[:limit]
				next = items[len(items)-1].AgentID
			}
			now := time.Now().UTC()
			for i := range items {
				items[i].Evaluate(now, options.Policy.OfflineAfter, options.Policy.InventoryMaxAge)
			}
			writeJSON(w, map[string]any{"items": items, "next_cursor": next, "as_of": now})
			return
		case "/admin/api/alerts":
			if r.Method != "GET" {
				break
			}
			state := r.URL.Query().Get("state")
			if state == "" {
				state = "active"
			}
			if state != "active" && state != "resolved" && state != "all" {
				http.Error(w, "invalid alert state", 400)
				return
			}
			limit, e := integer(r, "limit", 50, 1, 1000)
			before, err := strconv.ParseInt(defaultString(r.URL.Query().Get("before"), "0"), 10, 64)
			if e != nil || err != nil || before < 0 {
				http.Error(w, "invalid pagination", 400)
				return
			}
			items, err := store.Alerts(r.Context(), state, before, limit+1)
			if err != nil {
				storageError(w, err)
				return
			}
			var next int64
			if len(items) > limit {
				items = items[:limit]
				next = items[len(items)-1].Sequence
			}
			writeJSON(w, map[string]any{"items": items, "next_before": next})
			return
		case "/admin/api/acknowledge":
			if r.Method != "POST" {
				break
			}
			var v struct {
				ID string `json:"id"`
			}
			if !decodeJSON(w, r, 1024, &v) {
				return
			}
			if !ingest.Identifier(v.ID) {
				http.Error(w, "invalid alert ID", 400)
				return
			}
			item, err := store.AcknowledgeAlert(r.Context(), v.ID, defaultString(session.User.Username, "administrator"))
			if err != nil {
				storageError(w, err)
				return
			}
			writeJSON(w, item)
			return
		case "/admin/api/inventory":
			if r.Method != "GET" {
				break
			}
			id := r.URL.Query().Get("id")
			section := defaultString(r.URL.Query().Get("section"), "components")
			offset, err := integer(r, "offset", 0, 0, 100000)
			if err != nil || len(id) < 1 || len(id) > 256 || section != "components" && section != "updates" {
				http.Error(w, "invalid inventory query", 400)
				return
			}
			value, err := store.AdminInventory(r.Context(), id, section, offset, 50)
			if err != nil {
				storageError(w, err)
				return
			}
			writeJSON(w, value)
			return
		}
		http.NotFound(w, r)
	}), nil
}
func defaultString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
func integer(r *http.Request, name string, fallback, min, max int) (int, error) {
	value := r.URL.Query().Get(name)
	if value == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(value)
	if err != nil || v < min || v > max {
		return 0, errors.New("invalid integer")
	}
	return v, nil
}
func decodeJSON(w http.ResponseWriter, r *http.Request, limit int64, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	defer r.Body.Close()
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(value) != nil {
		http.Error(w, "invalid JSON", 400)
		return false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		http.Error(w, "invalid JSON", 400)
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func storageError(w http.ResponseWriter, err error) {
	status := 503
	if errors.Is(err, ErrForbidden) {
		status = 403
	}
	if errors.Is(err, ErrInvalid) {
		status = 400
	}
	if errors.Is(err, domain.ErrNotFound) {
		status = 404
	}
	if errors.Is(err, domain.ErrConflict) {
		status = 409
	}
	http.Error(w, http.StatusText(status), status)
}
