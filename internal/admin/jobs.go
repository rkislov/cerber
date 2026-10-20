// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/jobs"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func jobManagement(store Store, w http.ResponseWriter, r *http.Request, monitor func() jobs.Status) bool {
	path := r.URL.Path
	if path != "/admin/api/jobs" && path != "/admin/api/schedules" {
		return false
	}
	if r.Method == "GET" {
		agent := r.URL.Query().Get("agent")
		if agent != "" && !ingest.Identifier(agent) {
			http.Error(w, "invalid agent", 400)
			return true
		}
		if path == "/admin/api/jobs" {
			before, err := strconv.ParseInt(defaultString(r.URL.Query().Get("before"), "0"), 10, 64)
			if err != nil || before < 0 {
				http.Error(w, "invalid cursor", 400)
				return true
			}
			items, err := store.Jobs(r.Context(), agent, before, 101)
			if err != nil {
				storageError(w, err)
				return true
			}
			var next int64
			if len(items) > 100 {
				items = items[:100]
				next = items[99].Sequence
			}
			status := jobs.Status{}
			if monitor != nil {
				status = monitor()
			}
			writeJSON(w, map[string]any{"items": items, "next_before": next, "as_of": time.Now().UTC(), "scheduler": status})
		} else {
			after := r.URL.Query().Get("after")
			if after != "" && !ingest.Identifier(after) {
				http.Error(w, "invalid cursor", 400)
				return true
			}
			items, err := store.JobSchedules(r.Context(), agent, after, 101)
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
	if r.Method != "POST" {
		return false
	}
	var c jobs.Command
	if !decodeJSON(w, r, 4096, &c) {
		return true
	}
	if (path == "/admin/api/schedules") != strings.HasPrefix(c.Action, "schedule.") {
		http.Error(w, "invalid action", 400)
		return true
	}
	id, err := store.JobCommand(r.Context(), c, time.Now().UTC())
	if err != nil {
		storageError(w, err)
		return true
	}
	writeJSON(w, map[string]string{"id": id})
	return true
}
