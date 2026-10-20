// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"errors"
	"github.com/rkislov/cerber/internal/incidents"
	"github.com/rkislov/cerber/internal/telemetry"
	"net/http"
	"time"
)

func incidentManagement(control Store, store EventStore, w http.ResponseWriter, r *http.Request, user User) bool {
	switch r.URL.Path {
	case "/admin/api/incidents", "/admin/api/incidents/history", "/admin/api/incidents/detections", "/admin/api/incidents/assignees":
	default:
		return false
	}
	fail := func(e error) {
		status := 503
		switch {
		case errors.Is(e, incidents.ErrInvalid):
			status = 400
		case errors.Is(e, incidents.ErrConflict):
			status = 409
		case errors.Is(e, incidents.ErrNotFound):
			status = 404
		}
		http.Error(w, http.StatusText(status), status)
	}
	if r.URL.Path == "/admin/api/incidents/assignees" {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", 405)
			return true
		}
		after := r.URL.Query().Get("after")
		if after != "" && !ValidUsername(after) {
			http.Error(w, "invalid cursor", 400)
			return true
		}
		users, e := control.AdminUsers(r.Context(), after, 101)
		if e != nil {
			storageError(w, e)
			return true
		}
		next := ""
		if len(users) > 100 {
			users = users[:100]
			next = users[99].Username
		}
		allowed := []User{}
		for _, u := range users {
			if !u.Disabled && u.Role != "viewer" {
				allowed = append(allowed, u)
			}
		}
		writeJSON(w, map[string]any{"items": allowed, "next_cursor": next})
		return true
	}
	if store == nil {
		if r.Method == "GET" {
			writeJSON(w, map[string]any{"enabled": false, "items": []any{}})
		} else {
			http.Error(w, "incident storage not enabled", 503)
		}
		return true
	}
	if r.Method == "POST" {
		if r.URL.Path != "/admin/api/incidents" {
			http.Error(w, "method not allowed", 405)
			return true
		}
		var c incidents.Command
		if !decodeJSON(w, r, 32768, &c) {
			return true
		}
		if c.Action == "create" || c.Action == "update" {
			if c.Assignee != "" {
				u, e := control.AdminUser(r.Context(), c.Assignee)
				if e != nil || u.Disabled || u.Role == "viewer" {
					http.Error(w, "assignee must be an active analyst, operator or administrator", 400)
					return true
				}
			}
		}
		actor := user.Username
		if actor == "" {
			actor = "legacy-administrator"
		}
		v, e := store.IncidentCommand(r.Context(), c, actor, time.Now().UTC())
		if e != nil {
			fail(e)
			return true
		}
		writeJSON(w, v)
		return true
	}
	before, e := integer(r, "before", 0, 0, int(^uint(0)>>1))
	if e != nil {
		http.Error(w, "invalid cursor", 400)
		return true
	}
	id := r.URL.Query().Get("id")
	if r.URL.Path == "/admin/api/incidents" && id == "" {
		items, e := store.Incidents(r.Context(), int64(before), r.URL.Query().Get("state"), r.URL.Query().Get("severity"), r.URL.Query().Get("assignee"), 101)
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
		return true
	}
	if !telemetry.Identifier(id) {
		http.Error(w, "invalid incident", 400)
		return true
	}
	card, e := store.Incident(r.Context(), id)
	if e != nil {
		fail(e)
		return true
	}
	switch r.URL.Path {
	case "/admin/api/incidents":
		writeJSON(w, card)
	case "/admin/api/incidents/history":
		items, e := store.IncidentHistory(r.Context(), id, int64(before), 101)
		if e != nil {
			fail(e)
			return true
		}
		next := int64(0)
		if len(items) > 100 {
			items = items[:100]
			next = items[99].Sequence
		}
		writeJSON(w, map[string]any{"items": items, "next_before": next})
	case "/admin/api/incidents/detections":
		items, e := store.IncidentDetections(r.Context(), id, int64(before), 101)
		if e != nil {
			fail(e)
			return true
		}
		next := int64(0)
		if len(items) > 100 {
			items = items[:100]
			next = items[99].Sequence
		}
		writeJSON(w, map[string]any{"items": items, "next_before": next})
	}
	return true
}
