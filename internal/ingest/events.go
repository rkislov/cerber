// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/cerber/internal/telemetry"
	"io"
	"mime"
	"net/http"
	"strings"
)

type EventJournal interface {
	Accept(context.Context, string, string, telemetry.Batch) (telemetry.Receipt, error)
}
type EventBindings interface {
	AgentBinding(context.Context, string, string) (string, error)
}

func NewEventHandler(bindings EventBindings, journal EventJournal) http.Handler {
	slots := make(chan struct{}, 4)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Path != "/v1/agent/events" {
			http.NotFound(w, r)
			return
		}
		if r.Method != "POST" {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", 405)
			return
		}
		id := r.Header.Get("X-Cerber-Agent")
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, "Bearer ")
		if !Identifier(id) || token == auth || len(token) < 32 || len(token) > 512 {
			http.Error(w, "unauthorized", 401)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "30")
			http.Error(w, "receiver busy", 429)
			return
		}
		asset, e := bindings.AgentBinding(r.Context(), id, Hash([]byte(token)))
		if e != nil {
			status := 503
			if errors.Is(e, ErrUnauthorized) {
				status = 401
			}
			http.Error(w, http.StatusText(status), status)
			return
		}
		media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if e != nil || media != "application/json" {
			http.Error(w, "JSON required", 415)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, telemetry.MaxBatchBytes)
		defer r.Body.Close()
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		var b telemetry.Batch
		var extra any
		if e = d.Decode(&b); e != nil {
			var large *http.MaxBytesError
			if errors.As(e, &large) {
				http.Error(w, "batch too large", 413)
			} else {
				http.Error(w, "invalid batch", 400)
			}
			return
		}
		if d.Decode(&extra) != io.EOF || b.Validate() != nil {
			http.Error(w, "invalid batch", 400)
			return
		}
		if b.AgentID != id {
			http.Error(w, "identity mismatch", 403)
			return
		}
		// Recheck revocation immediately before durable acceptance. The journal contains
		// server-bound ownership, never an asset supplied by the agent.
		if _, e = bindings.AgentBinding(r.Context(), id, Hash([]byte(token))); e != nil {
			http.Error(w, "authentication unavailable or revoked", 401)
			return
		}
		receipt, e := journal.Accept(r.Context(), id, asset, b)
		if e != nil {
			if errors.Is(e, telemetry.ErrStorageProtected) || errors.Is(e, telemetry.ErrFull) {
				w.Header().Set("Retry-After", "60")
				w.Header().Set("X-Cerber-Backpressure", "storage")
			}
			status := 503
			if errors.Is(e, telemetry.ErrConflict) {
				status = 409
			}
			http.Error(w, http.StatusText(status), status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(receipt)
	})
}
func (c *Client) SendEvents(ctx context.Context, b telemetry.Batch) (telemetry.Receipt, error) {
	var r telemetry.Receipt
	if b.AgentID != c.credentials.AgentID || b.Validate() != nil {
		return r, telemetry.ErrInvalid
	}
	p, _ := json.Marshal(b)
	req, e := http.NewRequestWithContext(ctx, "POST", c.origin+"/v1/agent/events", bytes.NewReader(p))
	if e != nil {
		return r, e
	}
	req.Header.Set("Authorization", "Bearer "+c.credentials.Token)
	req.Header.Set("X-Cerber-Agent", b.AgentID)
	req.Header.Set("Content-Type", "application/json")
	resp, e := c.http.Do(req)
	if e != nil {
		return r, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return r, fmt.Errorf("event delivery HTTP %d; batch retained", resp.StatusCode)
	}
	d := json.NewDecoder(io.LimitReader(resp.Body, 8192))
	d.DisallowUnknownFields()
	var extra any
	if d.Decode(&r) != nil || d.Decode(&extra) != io.EOF || r.BatchID != b.ID || r.AgentID != b.AgentID || r.Count != len(b.Records) || r.ReceivedAt.IsZero() {
		return r, errors.New("event receipt mismatch; batch retained")
	}
	return r, nil
}
