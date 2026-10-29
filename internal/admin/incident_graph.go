// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"context"
	"errors"
	"github.com/rkislov/cerber/internal/correlation"
	"github.com/rkislov/cerber/internal/incidents"
	"net/http"
	"time"
)

func incidentGraphManagement(events EventStore, w http.ResponseWriter, r *http.Request, slots chan struct{}) bool {
	if r.URL.Path != "/admin/api/incident-graph" {
		return false
	}
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", 405)
		return true
	}
	source, ok := events.(interface {
		IncidentGraph(context.Context, string) (correlation.Investigation, error)
	})
	if !ok {
		http.Error(w, "incident graph unavailable", 503)
		return true
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		w.Header().Set("Retry-After", "5")
		http.Error(w, "incident graph busy", 429)
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	v, e := source.IncidentGraph(ctx, r.URL.Query().Get("id"))
	if e != nil {
		status := 503
		if errors.Is(e, incidents.ErrInvalid) {
			status = 400
		}
		if errors.Is(e, incidents.ErrNotFound) {
			status = 404
		}
		http.Error(w, http.StatusText(status), status)
	} else {
		writeJSON(w, map[string]any{"context": v})
	}
	return true
}
