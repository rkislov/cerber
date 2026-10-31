// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"context"
	"errors"
	"net/http"
	"sync"

	rules "github.com/rkislov/cerber/internal/suricatarules"
)

type suricataStore interface {
	SuricataCatalog(context.Context) ([]rules.Manifest, string, error)
	SuricataBundle(context.Context, string) (rules.Bundle, error)
	PutSuricataBundle(context.Context, rules.Bundle) (rules.Manifest, error)
	DeleteSuricataBundle(context.Context, string) error
	SuricataAssignment(context.Context, string) (rules.Assignment, error)
	AssignSuricata(context.Context, rules.Change) (rules.Assignment, error)
	SuricataHistory(context.Context, string) ([]map[string]any, error)
}
type suricataService struct{ work sync.Mutex }

func (h *suricataService) serve(base Store, w http.ResponseWriter, r *http.Request, u User) bool {
	if serveSuricataAutomation(base, w, r, u) {
		return true
	}
	if r.URL.Path != "/admin/api/suricata" {
		return false
	}
	s, ok := base.(suricataStore)
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
		case errors.Is(e, rules.ErrLimit):
			code = 507
		case errors.Is(e, rules.ErrNotFound):
			code = 404
		case errors.Is(e, ErrForbidden):
			code = 403
		}
		http.Error(w, http.StatusText(code), code)
	}
	if r.Method == "GET" {
		versions, key, e := s.SuricataCatalog(r.Context())
		if e != nil {
			fail(e)
			return true
		}
		job := map[string]any{"running": false, "message": "Расписание, состояние и история ET Open — ниже."}
		if automation, ok := base.(suricataAutomationStore); ok {
			feeds, e := automation.SuricataFeeds(r.Context())
			if e != nil {
				fail(e)
				return true
			}
			for _, f := range feeds {
				if f.State == "downloading" || f.Requested {
					job["running"] = true
					job["message"] = "Обновление ET Open выполняется планировщиком"
				}
			}
		}

		response := map[string]any{"versions": versions, "public_key": key, "download": job, "max_versions": rules.MaxVersions, "max_storage": rules.MaxStorage, "source_url": rules.ETURL}
		if id := r.URL.Query().Get("agent"); id != "" {
			a, e := s.SuricataAssignment(r.Context(), id)
			if e != nil {
				fail(e)
				return true
			}
			history, e := s.SuricataHistory(r.Context(), id)
			if e != nil {
				fail(e)
				return true
			}
			response["assignment"] = a
			response["history"] = history
		}
		writeJSON(w, response)
		return true
	}
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return true
	}
	if u.Role != "administrator" || u.Username == "" {
		fail(ErrForbidden)
		return true
	}
	var c struct {
		Action      string       `json:"action"`
		Name        string       `json:"name"`
		Rules       string       `json:"rules"`
		BaseID      string       `json:"base_id"`
		EngineMajor int          `json:"engine_major"`
		ID          string       `json:"id"`
		Change      rules.Change `json:"change"`
	}
	if !decodeJSON(w, r, 2<<20, &c) {
		return true
	}
	if !h.work.TryLock() {
		http.Error(w, "rule operation running", 429)
		return true
	}
	defer h.work.Unlock()
	switch c.Action {
	case "download":
		if c.EngineMajor != 7 && c.EngineMajor != 8 {
			fail(rules.ErrInvalid)
			return true
		}
		automation, ok := base.(suricataAutomationStore)
		if !ok {
			http.Error(w, "scheduler unavailable", 503)
			return true
		}
		feeds, e := automation.SuricataFeeds(r.Context())
		if e != nil {
			fail(e)
			return true
		}
		for _, f := range feeds {
			if f.EngineMajor == c.EngineMajor {
				_, e = automation.SetSuricataFeed(r.Context(), rules.FeedChange{EngineMajor: c.EngineMajor, ExpectedRevision: f.Revision, RunNow: true})
				if e != nil {
					fail(e)
					return true
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		writeJSON(w, map[string]bool{"started": true})

	case "upload":
		if len(c.Rules) > 1<<20 {
			fail(rules.ErrLimit)
			return true
		}
		data := []byte(c.Rules)
		source := "custom"
		if c.BaseID != "" {
			b, e := s.SuricataBundle(r.Context(), c.BaseID)
			if e != nil {
				fail(e)
				return true
			}
			if b.Manifest.EngineMajor != c.EngineMajor {
				fail(rules.ErrInvalid)
				return true
			}
			plain, e := rules.Unpack(b.Manifest, b.Data)
			if e != nil {
				fail(e)
				return true
			}
			data = append(plain, data...)
			source = "combined"
		}
		b, e := rules.Pack(c.Name, source, c.EngineMajor, data)
		if e != nil {
			if errors.Is(e, rules.ErrInvalid) {
				w.WriteHeader(400)
				writeJSON(w, map[string]string{"error": e.Error()})
			} else {
				fail(e)
			}
			return true
		}
		m, e := s.PutSuricataBundle(r.Context(), b)
		if e != nil {
			fail(e)
		} else {
			writeJSON(w, m)
		}
	case "assign":
		a, e := s.AssignSuricata(r.Context(), c.Change)
		if e != nil {
			fail(e)
		} else {
			writeJSON(w, a)
		}
	case "delete":
		if e := s.DeleteSuricataBundle(r.Context(), c.ID); e != nil {
			fail(e)
		} else {
			writeJSON(w, map[string]bool{"deleted": true})
		}
	default:
		fail(rules.ErrInvalid)
	}
	return true
}
