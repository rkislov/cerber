// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"context"
	"errors"
	"github.com/rkislov/cerber/internal/directory"
	"github.com/rkislov/cerber/internal/integrations"
	"net/http"
	"time"
)

func integrationManagement(store *integrations.Store, w http.ResponseWriter, r *http.Request, user User, slots chan struct{}, workers ...*integrations.Worker) bool {
	if r.URL.Path != "/admin/api/settings/check-directory-account" && r.URL.Path != "/admin/api/settings/test-directory" && r.URL.Path != "/admin/api/settings/runtime" && r.URL.Path != "/admin/api/settings/sync-threatfox" && r.URL.Path != "/admin/api/settings" && r.URL.Path != "/admin/api/settings/test-smtp" && r.URL.Path != "/admin/api/settings/test-threatfox" {
		return false
	}
	if user.Role != "administrator" || user.Username == "" {
		http.Error(w, "forbidden", 403)
		return true
	}
	var worker *integrations.Worker
	if len(workers) > 0 {
		worker = workers[0]
	}
	if r.URL.Path == "/admin/api/settings/runtime" {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", 405)
			return true
		}
		if worker == nil {
			http.Error(w, "worker unavailable", 503)
			return true
		}
		writeJSON(w, worker.Status(r.Context()))
		return true
	}
	if r.URL.Path == "/admin/api/settings/sync-threatfox" {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return true
		}
		if worker == nil {
			http.Error(w, "worker unavailable", 503)
			return true
		}
		worker.Sync()
		writeJSON(w, map[string]bool{"ok": true})
		return true
	}
	if store == nil {
		if r.Method == "GET" && r.URL.Path == "/admin/api/settings" {
			writeJSON(w, integrations.View{Configured: false})
		} else {
			http.Error(w, "settings storage is not configured", 503)
		}
		return true
	}
	if r.URL.Path == "/admin/api/settings" {
		if r.Method == "GET" {
			writeJSON(w, store.View())
			return true
		}
		var c integrations.Command
		if !decodeJSON(w, r, 32768, &c) {
			return true
		}
		if e := store.Save(c, user.Username); e != nil {
			status := 503
			if errors.Is(e, integrations.ErrInvalid) {
				status = 400
			}
			if errors.Is(e, integrations.ErrConflict) {
				status = 409
			}
			http.Error(w, http.StatusText(status), status)
			return true
		}
		if worker != nil && c.Scope == "threatfox" {
			worker.Sync()
		}
		writeJSON(w, store.View())
		return true
	}
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return true
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		http.Error(w, "connection probes busy", 429)
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if r.URL.Path == "/admin/api/settings/check-directory-account" {
		var q directory.Query
		if !decodeJSON(w, r, 2048, &q) {
			return true
		}
		p, e := directory.Check(ctx, store.DirectoryConfig(), q)
		if e != nil {
			writeJSON(w, map[string]any{"ok": false, "message": e.Error()})
		} else {
			writeJSON(w, map[string]any{"ok": p.State == "verified", "message": p.State, "account": p})
		}
		return true
	}
	if r.URL.Path == "/admin/api/settings/test-directory" {
		d, e := store.ProbeDirectory(ctx)
		if e != nil {
			writeJSON(w, map[string]any{"ok": false, "message": e.Error()})
		} else {
			writeJSON(w, map[string]any{"ok": true, "message": "Домен подтверждён: " + d.NetBIOS + " ↔ " + d.DNS + " · " + d.SID, "domain": d})
		}
		return true
	}
	var e error
	if r.URL.Path == "/admin/api/settings/test-smtp" {
		e = store.ProbeSMTP(ctx)
	} else {
		e = store.ProbeThreatFox(ctx)
	}
	if errors.Is(e, integrations.ErrInvalid) {
		e = errors.New("Сначала сохраните адрес SMTP или ключ ThreatFox для выбранной проверки.")
	}
	if e != nil {
		writeJSON(w, map[string]any{"ok": false, "message": e.Error()})
	} else {
		writeJSON(w, map[string]any{"ok": true, "message": "Соединение и авторизация проверены. Сообщения не отправлялись."})
	}
	return true
}
