// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"context"
	"errors"
	"net/http"

	"github.com/rkislov/cerber/internal/jobs"
	rules "github.com/rkislov/cerber/internal/suricatarules"
)

type suricataAutomationStore interface {
	SuricataFeeds(context.Context) ([]rules.Feed, error)
	SetSuricataFeed(context.Context, rules.FeedChange) (rules.Feed, error)
	SuricataGroups(context.Context) ([]rules.GroupView, error)
	SetSuricataGroup(context.Context, rules.GroupChange) (rules.GroupPolicy, error)
	SuricataAutomationHistory(context.Context, string) ([]map[string]any, error)
	AgentGroups(context.Context, string, string, int) ([]jobs.Group, error)
}

func serveSuricataAutomation(base Store, w http.ResponseWriter, r *http.Request, u User) bool {
	if r.URL.Path != "/admin/api/suricata-automation" {
		return false
	}
	s, ok := base.(suricataAutomationStore)
	if !ok {
		http.Error(w, "unavailable", 503)
		return true
	}
	fail := func(e error) {
		code := 503
		switch {
		case errors.Is(e, rules.ErrInvalid):
			code = 400
		case errors.Is(e, rules.ErrConflict):
			code = 409
		case errors.Is(e, rules.ErrNotFound):
			code = 404
		case errors.Is(e, rules.ErrLimit):
			code = 507
		case errors.Is(e, ErrForbidden):
			code = 403
		}
		http.Error(w, http.StatusText(code), code)
	}
	if r.Method == "GET" {
		feeds, e := s.SuricataFeeds(r.Context())
		if e != nil {
			fail(e)
			return true
		}
		groups, e := s.SuricataGroups(r.Context())
		if e != nil {
			fail(e)
			return true
		}
		choices := []jobs.Group{}
		after := ""
		for len(choices) < 500 {
			page, e := s.AgentGroups(r.Context(), "active", after, 100)
			if e != nil {
				fail(e)
				return true
			}
			choices = append(choices, page...)
			if len(page) < 100 {
				break
			}
			after = page[len(page)-1].ID
		}
		history, e := s.SuricataAutomationHistory(r.Context(), r.URL.Query().Get("history"))
		if e != nil {
			fail(e)
			return true
		}
		writeJSON(w, map[string]any{"feeds": feeds, "groups": groups, "group_choices": choices, "history": history})
		return true
	}
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return true
	}
	if u.Username == "" || u.Role != "administrator" {
		fail(ErrForbidden)
		return true
	}
	var c struct {
		Action string            `json:"action"`
		Feed   rules.FeedChange  `json:"feed"`
		Group  rules.GroupChange `json:"group"`
	}
	if !decodeJSON(w, r, 16384, &c) {
		return true
	}
	switch c.Action {
	case "feed":
		v, e := s.SetSuricataFeed(r.Context(), c.Feed)
		if e != nil {
			fail(e)
		} else {
			writeJSON(w, v)
		}
	case "group":
		v, e := s.SetSuricataGroup(r.Context(), c.Group)
		if e != nil {
			fail(e)
		} else {
			writeJSON(w, v)
		}
	default:
		fail(rules.ErrInvalid)
	}
	return true
}
