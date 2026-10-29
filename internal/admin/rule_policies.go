// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"context"
	"errors"
	"github.com/rkislov/cerber/internal/correlation"
	"github.com/rkislov/cerber/internal/integrations"
	"github.com/rkislov/cerber/internal/rulepolicy"
	"github.com/rkislov/cerber/internal/rulepreview"
	"net/http"
	"time"
)

type correlationPolicies interface {
	RulePolicies(context.Context) ([]rulepolicy.Version, error)
	RulePolicyHistory(context.Context, string, int64) ([]rulepolicy.Version, error)
	RulePolicyVersion(context.Context, string, int64) (rulepolicy.Version, error)
	ChangeRulePolicy(context.Context, rulepolicy.Change, string) (rulepolicy.Version, error)
	PreviewRule(context.Context, rulepreview.Request, *integrations.Index, string) (rulepreview.Result, error)
}

func rulePolicyManagement(control Store, events EventStore, worker *integrations.Worker, w http.ResponseWriter, r *http.Request, user User, slots chan struct{}) bool {
	if r.URL.Path != "/admin/api/rule-policies" && r.URL.Path != "/admin/api/rule-policies/history" && r.URL.Path != "/admin/api/rule-policies/preview" {
		return false
	}
	store, ok := events.(correlationPolicies)
	if !ok {
		http.Error(w, "correlation policy storage unavailable", 503)
		return true
	}
	fail := func(e error) {
		status := 503
		switch {
		case errors.Is(e, rulepolicy.ErrInvalid):
			status = 400
		case errors.Is(e, rulepolicy.ErrConflict):
			status = 409
		case errors.Is(e, rulepolicy.ErrNotFound):
			status = 404
		}
		http.Error(w, http.StatusText(status), status)
	}
	groupsValid := func(cfg rulepolicy.Config) bool {
		for _, id := range cfg.GroupIDs {
			g, e := control.AgentGroup(r.Context(), id)
			if e != nil || g.Archived {
				http.Error(w, "group missing or archived", 400)
				return false
			}
		}
		return true
	}
	if r.Method == "GET" {
		if r.URL.Path == "/admin/api/rule-policies" {
			items, e := store.RulePolicies(r.Context())
			if e != nil {
				fail(e)
			} else {
				writeJSON(w, map[string]any{"items": items, "catalog": correlation.Catalog()})
			}
			return true
		}
		if r.URL.Path == "/admin/api/rule-policies/history" {
			id := r.URL.Query().Get("id")
			before, e := integer(r, "before", 0, 0, int(^uint(0)>>1))
			if e != nil {
				fail(rulepolicy.ErrInvalid)
				return true
			}
			if raw := r.URL.Query().Get("revision"); raw != "" {
				revision, e := integer(r, "revision", 0, 1, int(^uint(0)>>1))
				if e != nil {
					fail(rulepolicy.ErrInvalid)
					return true
				}
				v, e := store.RulePolicyVersion(r.Context(), id, int64(revision))
				if e != nil {
					fail(e)
				} else {
					writeJSON(w, v)
				}
				return true
			}
			items, e := store.RulePolicyHistory(r.Context(), id, int64(before))
			if e != nil {
				fail(e)
				return true
			}
			next := int64(0)
			if len(items) > 50 {
				items = items[:50]
				next = items[49].Revision
			}
			writeJSON(w, map[string]any{"items": items, "next_before": next})
			return true
		}
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", 405)
		return true
	}
	if user.Username == "" {
		http.Error(w, "named account required", 403)
		return true
	}
	if r.URL.Path == "/admin/api/rule-policies/preview" {
		if user.Role != "administrator" && user.Role != "operator" && user.Role != "analyst" {
			http.Error(w, "forbidden", 403)
			return true
		}
		var req rulepreview.Request
		if !decodeJSON(w, r, 32768, &req) {
			return true
		}
		cfg, e := rulepolicy.Canonical(req.Rule, req.Config)
		if e != nil {
			fail(e)
			return true
		}
		req.Config = cfg
		if !groupsValid(cfg) {
			return true
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "5")
			http.Error(w, "preview busy", 429)
			return true
		}
		var index *integrations.Index
		revision := ""
		if worker != nil {
			index, revision = worker.RulePreviewIndex()
		}
		if (req.Rule == "threatfox.ip_match" || req.Rule == "threatfox.ioc_match") && index == nil {
			http.Error(w, "IOC feed unavailable", 503)
			return true
		}
		ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
		defer cancel()
		v, e := store.PreviewRule(ctx, req, index, revision)
		if e != nil {
			fail(e)
		} else {
			writeJSON(w, v)
		}
		return true
	}
	if r.URL.Path != "/admin/api/rule-policies" {
		http.Error(w, "method not allowed", 405)
		return true
	}
	if user.Role != "administrator" {
		http.Error(w, "forbidden", 403)
		return true
	}
	var c rulepolicy.Change
	if !decodeJSON(w, r, 16384, &c) {
		return true
	}
	cfg := c.Config
	if c.Action == "rollback" {
		target, e := store.RulePolicyVersion(r.Context(), c.Rule, c.TargetRevision)
		if e != nil {
			fail(e)
			return true
		}
		cfg = target.Config
	}
	canonical, e := rulepolicy.Canonical(c.Rule, cfg)
	if e != nil {
		fail(e)
		return true
	}
	if !groupsValid(canonical) {
		return true
	}
	c.Config = canonical
	v, e := store.ChangeRulePolicy(r.Context(), c, user.Username)
	if e != nil {
		fail(e)
	} else {
		writeJSON(w, v)
	}
	return true
}
