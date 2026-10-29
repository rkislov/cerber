// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"context"
	"errors"
	"github.com/rkislov/cerber/internal/correlation"
	"github.com/rkislov/cerber/internal/endpoint"
	"github.com/rkislov/cerber/internal/incidents"
	"net/http"
	"time"
)

func investigationManagement(store EventStore, server *endpoint.Server, w http.ResponseWriter, r *http.Request, slots chan struct{}) bool {
	if r.URL.Path != "/admin/api/investigation" {
		return false
	}
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", 405)
		return true
	}
	source, ok := store.(interface {
		Investigation(context.Context, string, string) (correlation.Investigation, error)
	})
	if !ok {
		http.Error(w, "investigation unavailable", 503)
		return true
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		w.Header().Set("Retry-After", "5")
		http.Error(w, "investigation busy", 429)
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	v, e := source.Investigation(ctx, r.URL.Query().Get("incident"), r.URL.Query().Get("detection"))
	if e != nil {
		status := 503
		if errors.Is(e, incidents.ErrInvalid) {
			status = 400
		}
		if errors.Is(e, incidents.ErrNotFound) {
			status = 404
		}
		http.Error(w, http.StatusText(status), status)
		return true
	}
	assets := []endpoint.InvestigationAsset{}
	assetError := ""
	truncated := false
	if server != nil {
		assets, truncated, e = server.InvestigationAssets(ctx, v.Anchors)
		if e != nil {
			assets = []endpoint.InvestigationAsset{}
			assetError = "Не удалось прочитать контекст уязвимостей; связь с эксплуатацией не установлена"
		}
	}
	writeJSON(w, map[string]any{"context": v, "assets": assets, "assets_truncated": truncated, "asset_error": assetError})
	return true
}
