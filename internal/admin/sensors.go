// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"context"
	"errors"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/sensorstate"
	"net/http"
	"time"
)

type sensorStore interface {
	SensorStatuses(context.Context, string, int) ([]ingest.AgentStatus, error)
	SensorPolicy(context.Context, string) (sensorstate.Policy, error)
	ChangeSensorPolicy(context.Context, sensorstate.Change) (sensorstate.Policy, error)
}

func sensorManagement(base Store, w http.ResponseWriter, r *http.Request, user User, policy alerts.Policy) bool {
	if r.URL.Path != "/admin/api/sensors" && r.URL.Path != "/admin/api/sensors/history" {
		return false
	}
	s, ok := base.(sensorStore)
	if !ok {
		http.Error(w, "sensor storage unavailable", 503)
		return true
	}
	fail := func(e error) {
		code := 503
		switch {
		case errors.Is(e, sensorstate.ErrInvalid):
			code = 400
		case errors.Is(e, sensorstate.ErrConflict):
			code = 409
		case errors.Is(e, sensorstate.ErrNotFound):
			code = 404
		case errors.Is(e, ErrForbidden):
			code = 403
		}
		http.Error(w, http.StatusText(code), code)
	}
	if r.URL.Path == "/admin/api/sensors/history" {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", 405)
			return true
		}
		h, ok := base.(interface {
			SensorHistory(context.Context, string, string, string, time.Time) (sensorstate.History, error)
		})
		if !ok {
			http.Error(w, "history unavailable", 503)
			return true
		}
		q := r.URL.Query()
		v, e := h.SensorHistory(r.Context(), q.Get("agent"), q.Get("input"), q.Get("period"), time.Now().UTC())
		if e != nil {
			fail(e)
		} else {
			writeJSON(w, v)
		}
		return true
	}
	if r.Method == "GET" {
		after := r.URL.Query().Get("after")
		if after != "" && !ingest.Identifier(after) {
			fail(sensorstate.ErrInvalid)
			return true
		}
		rows, e := s.SensorStatuses(r.Context(), after, 51)
		if e != nil {
			fail(e)
			return true
		}
		next := ""
		if len(rows) > 50 {
			rows = rows[:50]
			next = rows[49].AgentID
		}
		type item struct {
			Agent   ingest.AgentStatus        `json:"agent"`
			Policy  sensorstate.Policy        `json:"policy"`
			Monitor sensorstate.MonitorConfig `json:"monitor"`
		}
		items := []item{}
		now := time.Now().UTC()
		for _, a := range rows {
			a.Evaluate(now, policy.OfflineAfter, policy.InventoryMaxAge)
			p, e := s.SensorPolicy(r.Context(), a.AgentID)
			if e != nil {
				fail(e)
				return true
			}
			items = append(items, item{a, p, p.MonitorConfig()})
		}
		writeJSON(w, map[string]any{"items": items, "next_cursor": next, "as_of": now})
		return true
	}
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return true
	}
	if user.Username == "" || user.Role != "administrator" {
		fail(ErrForbidden)
		return true
	}
	var c sensorstate.Change
	if !decodeJSON(w, r, 65536, &c) {
		return true
	}
	p, e := s.ChangeSensorPolicy(r.Context(), c)
	if e != nil {
		fail(e)
	} else {
		writeJSON(w, p)
	}
	return true
}
