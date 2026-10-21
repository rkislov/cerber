// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"context"
	"errors"
	"fmt"
	"github.com/rkislov/cerber/internal/telemetry"
	"net/http"
	"time"
)

type LifecycleStore interface {
	RetentionStatus(context.Context) (telemetry.RetentionStatus, error)
	SetRetention(context.Context, telemetry.RetentionPolicy, string, time.Time) error
	Archives(context.Context, int64) ([]telemetry.Archive, error)
	RetentionHistory(context.Context, int64) ([]telemetry.RetentionAudit, error)
	ReadArchive(context.Context, string) ([]byte, telemetry.Archive, error)
	MaintainRequested(context.Context, string, time.Time) (int, error)
}

func lifecycleManagement(store EventStore, w http.ResponseWriter, r *http.Request, user User, slots chan struct{}) bool {
	switch r.URL.Path {
	case "/admin/api/event-retention", "/admin/api/event-archives", "/admin/api/event-retention-audit":
	default:
		return false
	}
	s, ok := store.(LifecycleStore)
	if !ok {
		if r.Method == "GET" {
			writeJSON(w, map[string]any{"enabled": false, "items": []any{}})
		} else {
			http.Error(w, "event storage disabled", 503)
		}
		return true
	}
	fail := func(e error) {
		status := 503
		if errors.Is(e, telemetry.ErrInvalid) {
			status = 400
		}
		if errors.Is(e, telemetry.ErrConflict) {
			status = 409
		}
		if errors.Is(e, telemetry.ErrNotFound) {
			status = 404
		}
		if errors.Is(e, telemetry.ErrExpired) {
			status = 410
		}
		http.Error(w, http.StatusText(status), status)
	}
	if r.Method == "POST" {
		if r.URL.Path != "/admin/api/event-retention" {
			http.Error(w, "method not allowed", 405)
			return true
		}
		if user.Role != "administrator" || user.Username == "" {
			http.Error(w, "named administrator required", 403)
			return true
		}
		var c struct {
			Action  string                    `json:"action"`
			Policy  telemetry.RetentionPolicy `json:"policy"`
			Confirm bool                      `json:"confirm"`
		}
		if !decodeJSON(w, r, 2048, &c) {
			return true
		}
		switch c.Action {
		case "configure":
			if c.Policy.Enabled && !c.Confirm {
				http.Error(w, "explicit retention confirmation required", 400)
				return true
			}
			if e := s.SetRetention(r.Context(), c.Policy, user.Username, time.Now().UTC()); e != nil {
				fail(e)
				return true
			}
		case "run":
			n, e := s.MaintainRequested(r.Context(), user.Username, time.Now().UTC())
			if e != nil {
				fail(e)
			} else {
				writeJSON(w, map[string]any{"archived": n})
			}
			return true
		default:
			http.Error(w, "invalid action", 400)
			return true
		}
	}
	if r.URL.Path == "/admin/api/event-retention" {
		v, e := s.RetentionStatus(r.Context())
		if e != nil {
			fail(e)
		} else {
			writeJSON(w, map[string]any{"enabled": true, "status": v})
		}
		return true
	}
	before, e := integer(r, "before", 0, 0, int(^uint(0)>>1))
	if e != nil {
		fail(telemetry.ErrInvalid)
		return true
	}
	if r.URL.Path == "/admin/api/event-retention-audit" {
		items, e := s.RetentionHistory(r.Context(), int64(before))
		if e != nil {
			fail(e)
			return true
		}
		next := int64(0)
		if len(items) > 50 {
			items = items[:50]
			next = items[49].Sequence
		}
		writeJSON(w, map[string]any{"enabled": true, "items": items, "next_before": next})
		return true
	}
	if id := r.URL.Query().Get("id"); id != "" {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "archive reader busy", 429)
			return true
		}
		data, a, e := s.ReadArchive(r.Context(), id)
		if e != nil {
			fail(e)
			return true
		}
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.jsonl.gz"`, a.ID))
		w.Header().Set("X-Archive-SHA256", a.SHA256)
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		w.Write(data)
		return true
	}
	items, e := s.Archives(r.Context(), int64(before))
	if e != nil {
		fail(e)
		return true
	}
	next := int64(0)
	if len(items) > 50 {
		items = items[:50]
		next = items[49].Sequence
	}
	writeJSON(w, map[string]any{"enabled": true, "items": items, "next_before": next})
	return true
}
