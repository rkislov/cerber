// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"github.com/rkislov/cerber/internal/endpoint"
	"net"
	"net/http"
	"net/url"
)

func endpointManagement(server *endpoint.Server, store Store, w http.ResponseWriter, r *http.Request, u User) bool {
	if r.URL.Path == "/admin/api/network" || r.URL.Path == "/admin/api/network-assessments" {
		return networkManagement(server, store, w, r, u)
	}
	if r.URL.Path != "/admin/api/endpoint" {
		return false
	}
	if server == nil {
		http.Error(w, "endpoint signing not configured", 503)
		return true
	}
	if r.Method == "GET" {
		v, e := server.View(r.Context())
		if e != nil {
			storageError(w, e)
		} else {
			writeJSON(w, v)
		}
		return true
	}
	if u.Role != "administrator" || u.Username == "" {
		http.Error(w, "forbidden", 403)
		return true
	}
	var c endpoint.Command
	if !decodeJSON(w, r, 64<<10, &c) {
		return true
	}
	agents, e := store.AgentStatuses(r.Context(), "", "", 1000)
	if e != nil {
		storageError(w, e)
		return true
	}
	known := map[string]bool{}
	protected := []string{}
	for _, a := range agents {
		if !a.Revoked {
			known[a.AgentID] = true
			protected = append(protected, a.AssetIP)
		}
	}
	if c.Action == "policy" {
		if c.Policy.GroupID != "" {
			members, e := store.AgentGroupMembers(r.Context(), c.Policy.GroupID, "", 1000)
			if e != nil {
				storageError(w, e)
				return true
			}
			c.Policy.Agents = nil
			for _, m := range members {
				c.Policy.Agents = append(c.Policy.Agents, m.AgentID)
			}
		}
		for _, id := range c.Policy.Agents {
			if !known[id] {
				http.Error(w, "unknown agent", 400)
				return true
			}
		}
	}
	if c.Action == "block" && !known[c.Agent] {
		http.Error(w, "unknown agent", 400)
		return true
	}
	if host, _, e := net.SplitHostPort(r.RemoteAddr); e == nil {
		protected = append(protected, host)
	}
	if origin, e := url.Parse(r.Header.Get("Origin")); e == nil {
		ctx := r.Context()
		ips, _ := net.DefaultResolver.LookupIPAddr(ctx, origin.Hostname())
		for _, ip := range ips {
			protected = append(protected, ip.IP.String())
		}
	}
	if e = server.Command(r.Context(), c, u.Username, protected); e != nil {
		http.Error(w, "Invalid command, policy conflict, protected IP or missing confirmation", 400)
	} else {
		writeJSON(w, map[string]bool{"ok": true})
	}
	return true
}

func networkManagement(server *endpoint.Server, store Store, w http.ResponseWriter, r *http.Request, u User) bool {
	if server == nil {
		http.Error(w, "endpoint signing not configured", 503)
		return true
	}
	if r.Method == "GET" && r.URL.Path == "/admin/api/network-assessments" {
		v, e := server.AssessmentHistory(r.Context(), r.URL.Query().Get("asset"), r.URL.Query().Get("finding"))
		if e != nil {
			storageError(w, e)
		} else {
			writeJSON(w, map[string]any{"items": v})
		}
		return true
	}
	if r.URL.Path == "/admin/api/network-assessments" {
		http.Error(w, "method not allowed", 405)
		return true
	}
	if r.Method == "GET" {
		v, e := server.NetworkView(r.Context())
		if e != nil {
			storageError(w, e)
		} else {
			writeJSON(w, v)
		}
		return true
	}
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return true
	}
	if u.Role != "administrator" || u.Username == "" {
		http.Error(w, "forbidden", 403)
		return true
	}
	var c endpoint.NetworkCommand
	if !decodeJSON(w, r, 64<<10, &c) {
		return true
	}
	if c.Action == "create" {
		agents, e := store.AgentStatuses(r.Context(), "", "", 1000)
		if e != nil {
			storageError(w, e)
			return true
		}
		known := false
		for _, a := range agents {
			if a.AgentID == c.Plan.Agent && !a.Revoked {
				known = true
			}
		}
		if !known {
			http.Error(w, "unknown agent", 400)
			return true
		}
	}
	if e := server.NetworkCommand(r.Context(), c, u.Username); e != nil {
		http.Error(w, "Invalid network assignment or target range", 400)
	} else {
		writeJSON(w, map[string]bool{"ok": true})
	}
	return true
}
