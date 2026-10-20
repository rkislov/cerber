// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"context"
	"errors"
	"github.com/rkislov/cerber/internal/correlation"
	"github.com/rkislov/cerber/internal/telemetry"
	"net/http"
)

type EventStore interface {
	telemetry.Reader
	Acknowledge(context.Context, string, string) error
}

func eventManagement(store EventStore, w http.ResponseWriter, r *http.Request, user User) bool {
	if r.URL.Path == "/admin/api/correlation-rules" {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", 405)
			return true
		}
		id := r.URL.Query().Get("id")
		if id == "" {
			writeJSON(w, map[string]any{"items": correlation.Catalog()})
			return true
		}
		version, e := integer(r, "version", 0, 1, 100000)
		if e != nil {
			http.Error(w, "invalid rule version", 400)
			return true
		}
		rule, e := correlation.Describe(id, version)
		if e != nil {
			http.Error(w, "rule version not found", 404)
			return true
		}
		writeJSON(w, rule)
		return true
	}
	if r.URL.Path != "/admin/api/security-events" && r.URL.Path != "/admin/api/detections" && r.URL.Path != "/admin/api/security-raw" {
		return false
	}
	if store == nil {
		writeJSON(w, map[string]any{"enabled": false, "items": []any{}})
		return true
	}
	fail := func(e error) {
		status := 503
		if errors.Is(e, telemetry.ErrInvalid) {
			status = 400
		}
		if errors.Is(e, telemetry.ErrNotFound) {
			status = 404
		}
		http.Error(w, http.StatusText(status), status)
	}
	before, e := integer(r, "before", 0, 0, int(^uint(0)>>1))
	if e != nil {
		http.Error(w, "invalid cursor", 400)
		return true
	}
	switch r.URL.Path {
	case "/admin/api/security-raw":
		if r.Method != "GET" {
			http.Error(w, "method not allowed", 405)
			return true
		}
		id := r.URL.Query().Get("id")
		if !telemetry.Identifier(id) {
			http.Error(w, "invalid id", 400)
			return true
		}
		raw, e := store.ReadRaw(r.Context(), id)
		if e != nil {
			fail(e)
			return true
		}
		writeJSON(w, map[string]any{"id": id, "agent_id": raw.AgentID, "asset_id": raw.AssetID, "source": raw.Raw.Source, "received_at": raw.ReceivedAt, "data": raw.Raw.Data})
		return true
	case "/admin/api/security-events":
		if r.Method != "GET" {
			http.Error(w, "method not allowed", 405)
			return true
		}
		q := telemetry.Query{Before: int64(before), AgentID: r.URL.Query().Get("agent"), Class: r.URL.Query().Get("class"), Status: r.URL.Query().Get("status"), Limit: 101}
		items, e := store.ReadEvents(r.Context(), q)
		if e != nil {
			fail(e)
			return true
		}
		next := int64(0)
		if len(items) > 100 {
			items = items[:100]
			next = items[99].Sequence
		}
		status, e := store.Status(r.Context())
		if e != nil {
			fail(e)
			return true
		}
		writeJSON(w, map[string]any{"enabled": true, "items": items, "next_before": next, "pipeline": status})
	case "/admin/api/detections":
		if r.Method == "POST" {
			var v struct {
				ID string `json:"id"`
			}
			if !decodeJSON(w, r, 1024, &v) {
				return true
			}
			actor := user.Username
			if actor == "" {
				actor = "legacy-administrator"
			}
			if e = store.Acknowledge(r.Context(), v.ID, actor); e != nil {
				fail(e)
				return true
			}
			writeJSON(w, map[string]bool{"ok": true})
			return true
		}
		items, e := store.ReadDetections(r.Context(), int64(before), 101)
		if e != nil {
			fail(e)
			return true
		}
		next := int64(0)
		if len(items) > 100 {
			items = items[:100]
			next = items[99].Sequence
		}
		writeJSON(w, map[string]any{"enabled": true, "items": items, "next_before": next})
	}
	return true
}
