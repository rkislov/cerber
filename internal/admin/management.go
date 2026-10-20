// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/ingest"
	"net/http"
)

func management(store Store, w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	if path == "/admin/api/users" && r.Method == "GET" {
		after := r.URL.Query().Get("after")
		if after != "" && !ValidUsername(after) {
			http.Error(w, "invalid cursor", 400)
			return true
		}
		users, err := store.AdminUsers(r.Context(), after, 101)
		if err != nil {
			storageError(w, err)
			return true
		}
		next := ""
		if len(users) > 100 {
			users = users[:100]
			next = users[99].Username
		}
		writeJSON(w, map[string]any{"items": users, "next_cursor": next})
		return true
	}
	if r.Method != "POST" || (path != "/admin/api/users" && path != "/admin/api/agents/manage") {
		return false
	}
	var c Command
	if !decodeJSON(w, r, 4096, &c) {
		return true
	}
	if path == "/admin/api/users" {
		if c.Action != "user.create" && c.Action != "user.update" {
			http.Error(w, "invalid action", 400)
			return true
		}
		if c.Password != "" {
			hash, err := HashPassword(c.Password)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return true
			}
			c.PasswordHash = hash
		}
		c.Password = ""
		if err := store.AdminCommand(r.Context(), c); err != nil {
			storageError(w, err)
			return true
		}
		writeJSON(w, map[string]bool{"ok": true})
		return true
	}
	if c.Action != "agent.enroll" && c.Action != "agent.revoke" {
		http.Error(w, "invalid action", 400)
		return true
	}
	token := ""
	if c.Action == "agent.enroll" {
		var err error
		c.AgentID, err = domain.NewID()
		if err != nil {
			storageError(w, err)
			return true
		}
		token, err = randomToken()
		if err != nil {
			storageError(w, err)
			return true
		}
		c.TokenHash = ingest.Hash([]byte(token))
		if c.IP != "" {
			c.AssetID, err = domain.NewID()
			if err != nil {
				storageError(w, err)
				return true
			}
		}
	}
	if err := store.AdminCommand(r.Context(), c); err != nil {
		storageError(w, err)
		return true
	}
	if token != "" {
		writeJSON(w, map[string]string{"agent_id": c.AgentID, "token": token, "asset_id": c.AssetID})
	} else {
		writeJSON(w, map[string]bool{"ok": true})
	}
	return true
}
