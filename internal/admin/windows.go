// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"context"
	"github.com/rkislov/cerber/internal/endpoint"
	"github.com/rkislov/cerber/internal/inventory"
	"net/http"
)

func windowsManagement(server *endpoint.Server, store Store, w http.ResponseWriter, r *http.Request, u User, slots chan struct{}) bool {
	if r.URL.Path != "/admin/api/windows-vulnerabilities" && r.URL.Path != "/admin/api/microsoft-catalog" {
		return false
	}
	if server == nil || server.Catalog == nil {
		http.Error(w, "vulnerability catalog unavailable", 503)
		return true
	}
	if r.URL.Path == "/admin/api/microsoft-catalog" {
		if r.Method == "GET" {
			writeJSON(w, server.Catalog.MicrosoftStatus(r.Context()))
			return true
		}
		if r.Method == "POST" {
			if u.Role != "administrator" || u.Username == "" {
				http.Error(w, "forbidden", 403)
				return true
			}
			var v struct {
				Action string `json:"action"`
			}
			if !decodeJSON(w, r, 1024, &v) {
				return true
			}
			if v.Action != "refresh" {
				http.Error(w, "invalid action", 400)
				return true
			}
			server.Catalog.RequestMicrosoft()
			writeJSON(w, map[string]bool{"queued": true})
			return true
		}
	} else if r.Method == "GET" {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "5")
			http.Error(w, "assessment busy", 429)
			return true
		}
		id := r.URL.Query().Get("id")
		offset, e := integer(r, "offset", 0, 0, 100000)
		if e != nil || len(id) == 0 || len(id) > 256 {
			http.Error(w, "invalid inventory query", 400)
			return true
		}
		source, ok := store.(interface {
			Inventory(context.Context, string) (inventory.Snapshot, error)
		})
		if !ok {
			http.Error(w, "inventory source unavailable", 503)
			return true
		}
		snapshot, e := source.Inventory(r.Context(), id)
		if e != nil {
			storageError(w, e)
			return true
		}
		report, e := server.Catalog.WindowsInventory(r.Context(), snapshot, offset, 50)
		if e != nil {
			storageError(w, e)
		} else {
			writeJSON(w, report)
		}
		return true
	}
	w.Header().Set("Allow", "GET")
	http.Error(w, "method not allowed", 405)
	return true
}
