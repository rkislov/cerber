// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"context"
	"errors"
	"github.com/rkislov/cerber/internal/attack"
	"github.com/rkislov/cerber/internal/correlation"
	"github.com/rkislov/cerber/internal/incidents"
	"github.com/rkislov/cerber/internal/telemetry"
	"net/http"
	"time"
)

type EventStore interface {
	telemetry.Reader
	Incident(context.Context, string) (incidents.Card, error)
	Incidents(context.Context, int64, string, string, string, int) ([]incidents.Card, error)
	IncidentCommand(context.Context, incidents.Command, string, time.Time) (incidents.Card, error)
	IncidentHistory(context.Context, string, int64, int) ([]incidents.Entry, error)
	IncidentDetections(context.Context, string, int64, int) ([]telemetry.Detection, error)
	Acknowledge(context.Context, string, string) error
}

func eventManagement(store EventStore, w http.ResponseWriter, r *http.Request, user User) bool {
	if r.URL.Path == "/admin/api/event-health" {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", 405)
			return true
		}
		s, ok := store.(interface {
			PipelineHealth(context.Context) (telemetry.PipelineHealth, error)
		})
		if !ok {
			writeJSON(w, map[string]any{"enabled": false})
			return true
		}
		v, e := s.PipelineHealth(r.Context())
		if e != nil {
			http.Error(w, "pipeline monitor unavailable", 503)
		} else {
			writeJSON(w, map[string]any{"enabled": true, "health": v})
		}
		return true
	}
	if r.URL.Path == "/admin/api/mitre" {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", 405)
		} else {
			writeJSON(w, attack.Catalog())
		}
		return true
	}
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
		if errors.Is(e, telemetry.ErrExpired) {
			status = 410
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
		writeJSON(w, map[string]any{"id": id, "agent_id": raw.AgentID, "asset_id": raw.AssetID, "source": raw.Raw.Source, "received_at": raw.ReceivedAt, "data": raw.Raw.Data, "archived": raw.Archived, "archive_id": raw.ArchiveID})
		return true
	case "/admin/api/security-events":
		if r.Method != "GET" {
			http.Error(w, "method not allowed", 405)
			return true
		}
		q := telemetry.Query{Before: int64(before), AgentID: r.URL.Query().Get("agent"), Class: r.URL.Query().Get("class"), Status: r.URL.Query().Get("status"), Limit: 101}
		q.TimeField = r.URL.Query().Get("time_field")
		q.Text = r.URL.Query().Get("q")
		q.Source = r.URL.Query().Get("source")
		q.User = r.URL.Query().Get("user")
		q.SourceIP = r.URL.Query().Get("ip")
		q.Code = r.URL.Query().Get("code")
		q.Outcome = r.URL.Query().Get("outcome")
		for key, target := range map[string]**time.Time{"from": &q.From, "until": &q.Until} {
			if value := r.URL.Query().Get(key); value != "" {
				at, err := time.Parse(time.RFC3339Nano, value)
				if err != nil {
					fail(telemetry.ErrInvalid)
					return true
				}
				*target = &at
			}
		}
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
