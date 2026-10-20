// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"net/http"
	"strconv"
	"time"

	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/jobs"
)

func groupManagement(store Store, w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	allowed := map[string]map[string]bool{
		"/admin/api/groups":            {"create": true, "update": true, "archive": true, "restore": true},
		"/admin/api/groups/members":    {"members.add": true, "members.remove": true},
		"/admin/api/groups/candidates": {},
		"/admin/api/group-runs":        {"run": true, "run.cancel": true},
		"/admin/api/group-run-members": {},
		"/admin/api/group-schedules":   {"schedule.create": true, "schedule.update": true, "schedule.enable": true, "schedule.disable": true},
	}
	actions, ok := allowed[path]
	if !ok {
		return false
	}
	if r.Method == "POST" {
		var c jobs.GroupCommand
		if !decodeJSON(w, r, 16384, &c) {
			return true
		}
		if !actions[c.Action] {
			http.Error(w, "invalid action", 400)
			return true
		}
		id, err := store.GroupCommand(r.Context(), c, time.Now().UTC())
		if err != nil {
			storageError(w, err)
			return true
		}
		writeJSON(w, map[string]string{"id": id})
		return true
	}
	if r.Method != "GET" {
		return false
	}
	group, after := r.URL.Query().Get("group"), r.URL.Query().Get("after")
	if group != "" && !ingest.Identifier(group) || after != "" && !ingest.Identifier(after) {
		http.Error(w, "invalid cursor or group", 400)
		return true
	}
	switch path {
	case "/admin/api/groups":
		id := r.URL.Query().Get("id")
		if id != "" {
			if !ingest.Identifier(id) {
				http.Error(w, "invalid group", 400)
				return true
			}
			g, err := store.AgentGroup(r.Context(), id)
			if err != nil {
				storageError(w, err)
				return true
			}
			writeJSON(w, g)
			return true
		}
		items, err := store.AgentGroups(r.Context(), defaultString(r.URL.Query().Get("state"), "active"), after, 101)
		if err != nil {
			storageError(w, err)
			return true
		}
		next := ""
		if len(items) > 100 {
			items = items[:100]
			next = items[99].ID
		}
		writeJSON(w, map[string]any{"items": items, "next_cursor": next})
	case "/admin/api/groups/members", "/admin/api/groups/candidates":
		if group == "" {
			http.Error(w, "group required", 400)
			return true
		}
		g, err := store.AgentGroup(r.Context(), group)
		if err != nil {
			storageError(w, err)
			return true
		}
		var items []jobs.GroupMember
		limit := 100
		if path == "/admin/api/groups/candidates" {
			limit = 50
			items, err = store.AgentGroupCandidates(r.Context(), group, r.URL.Query().Get("q"), after, 51)
		} else {
			items, err = store.AgentGroupMembers(r.Context(), group, after, 101)
		}
		if err != nil {
			storageError(w, err)
			return true
		}
		next := ""
		if len(items) > limit {
			items = items[:limit]
			next = items[limit-1].AgentID
		}
		writeJSON(w, map[string]any{"group": g, "items": items, "next_cursor": next})
	case "/admin/api/group-runs":
		id := r.URL.Query().Get("id")
		if id != "" {
			if !ingest.Identifier(id) {
				http.Error(w, "invalid run", 400)
				return true
			}
			v, err := store.AgentGroupRun(r.Context(), id)
			if err != nil {
				storageError(w, err)
				return true
			}
			writeJSON(w, v)
			return true
		}
		before, err := strconv.ParseInt(defaultString(r.URL.Query().Get("before"), "0"), 10, 64)
		if err != nil || before < 0 {
			http.Error(w, "invalid cursor", 400)
			return true
		}
		items, err := store.GroupRuns(r.Context(), group, before, 101)
		if err != nil {
			storageError(w, err)
			return true
		}
		var next int64
		if len(items) > 100 {
			items = items[:100]
			next = items[99].Sequence
		}
		writeJSON(w, map[string]any{"items": items, "next_before": next})
	case "/admin/api/group-run-members":
		id := r.URL.Query().Get("run")
		if !ingest.Identifier(id) {
			http.Error(w, "run required", 400)
			return true
		}
		run, err := store.AgentGroupRun(r.Context(), id)
		if err != nil {
			storageError(w, err)
			return true
		}
		items, err := store.GroupRunMembers(r.Context(), id, after, 101)
		if err != nil {
			storageError(w, err)
			return true
		}
		next := ""
		if len(items) > 100 {
			items = items[:100]
			next = items[99].AgentID
		}
		writeJSON(w, map[string]any{"run": run, "items": items, "next_cursor": next})
	case "/admin/api/group-schedules":
		items, err := store.GroupSchedules(r.Context(), group, after, 101)
		if err != nil {
			storageError(w, err)
			return true
		}
		next := ""
		if len(items) > 100 {
			items = items[:100]
			next = items[99].ID
		}
		writeJSON(w, map[string]any{"items": items, "next_cursor": next})
	}
	return true
}
