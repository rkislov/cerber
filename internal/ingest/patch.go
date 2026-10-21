// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/patch"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

type PatchReceiver interface {
	ClaimPatch(context.Context, string, string, time.Time) (*patch.Request, error)
	FinishPatch(context.Context, string, string, patch.Result, time.Time) error
}

func NewPatchHandler(s PatchReceiver, key ed25519.PrivateKey) http.Handler {
	slots := make(chan struct{}, 4)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}
		if r.URL.Path != "/v1/agent/patches/claim" && r.URL.Path != "/v1/agent/patches/finish" {
			http.NotFound(w, r)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "busy", 429)
			return
		}
		id := r.Header.Get("X-Cerber-Agent")
		a := r.Header.Get("Authorization")
		token := strings.TrimPrefix(a, "Bearer ")
		if !Identifier(id) || token == a || len(token) < 32 || len(token) > 512 {
			http.Error(w, "unauthorized", 401)
			return
		}
		media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if media != "application/json" {
			http.Error(w, "JSON required", 415)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
		defer r.Body.Close()
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		var result patch.Result
		var value any = &result
		if strings.HasSuffix(r.URL.Path, "/claim") {
			value = &struct{}{}
		}
		var extra any
		if d.Decode(value) != nil || d.Decode(&extra) != io.EOF {
			http.Error(w, "invalid request", 400)
			return
		}
		var v any
		var e error
		if strings.HasSuffix(r.URL.Path, "/claim") {
			var q *patch.Request
			q, e = s.ClaimPatch(r.Context(), id, Hash([]byte(token)), time.Now().UTC())
			var ticket *patch.Ticket
			if e == nil && q != nil {
				t, err := patch.Sign(*q, key)
				e = err
				ticket = &t
			}
			v = map[string]any{"ticket": ticket}
		} else {
			e = s.FinishPatch(r.Context(), id, Hash([]byte(token)), result, time.Now().UTC())
			v = map[string]bool{"ok": e == nil}
		}
		if e != nil {
			status := 503
			if errors.Is(e, ErrUnauthorized) {
				status = 401
			}
			if errors.Is(e, patch.ErrInvalid) {
				status = 400
			}
			if errors.Is(e, patch.ErrConflict) {
				status = 409
			}
			http.Error(w, http.StatusText(status), status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	})
}
func (c *Client) ClaimPatch(ctx context.Context) (*patch.Ticket, error) {
	var v struct {
		Ticket *patch.Ticket `json:"ticket"`
	}
	e := c.jobRequest(ctx, "/v1/agent/patches/claim", struct{}{}, &v)
	return v.Ticket, e
}
func (c *Client) FinishPatch(ctx context.Context, r patch.Result) error {
	var v struct {
		OK bool `json:"ok"`
	}
	if e := c.jobRequest(ctx, "/v1/agent/patches/finish", r, &v); e != nil {
		return e
	}
	if !v.OK {
		return patch.ErrConflict
	}
	return nil
}
