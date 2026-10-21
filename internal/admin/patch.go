// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"context"
	"errors"
	"github.com/rkislov/cerber/internal/patch"
	"net/http"
	"time"
)

type PatchStore interface {
	PatchCommand(context.Context, patch.Command, time.Time) (patch.Job, error)
	PatchJobs(context.Context, string) ([]patch.Job, error)
}

func patchManagement(store Store, w http.ResponseWriter, r *http.Request, enabled bool) bool {
	if r.URL.Path != "/admin/api/patches" {
		return false
	}
	s, ok := store.(PatchStore)
	if !ok {
		http.Error(w, "storage unavailable", 503)
		return true
	}
	if r.Method == "GET" {
		items, e := s.PatchJobs(r.Context(), r.URL.Query().Get("agent"))
		if e != nil {
			storageError(w, e)
		} else {
			writeJSON(w, map[string]any{"enabled": enabled, "items": items})
		}
		return true
	}
	if !enabled {
		http.Error(w, "patch signing is disabled", 503)
		return true
	}
	u, _ := Principal(r.Context())
	if u.Role != "administrator" || u.Username == "" {
		http.Error(w, "named administrator required", 403)
		return true
	}
	var c patch.Command
	if !decodeJSON(w, r, 64<<10, &c) {
		return true
	}
	v, e := s.PatchCommand(r.Context(), c, time.Now().UTC())
	if e != nil {
		if errors.Is(e, patch.ErrInvalid) {
			http.Error(w, "invalid patch request", 400)
		} else if errors.Is(e, patch.ErrConflict) {
			http.Error(w, "inventory changed, preview expired or another job is active", 409)
		} else {
			storageError(w, e)
		}
	} else {
		writeJSON(w, v)
	}
	return true
}
