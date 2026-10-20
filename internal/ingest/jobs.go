// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/cerber/internal/jobs"
	"io"
	"net/http"
	"time"
)

type JobReceiver interface {
	ClaimJob(context.Context, string, string, time.Time) (*jobs.Job, error)
	FinishJob(context.Context, string, string, jobs.Result, time.Time) error
}

func receiveJob(w http.ResponseWriter, r *http.Request, store JobReceiver, id, hash string) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer r.Body.Close()
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	var value jobs.Result
	if r.URL.Path == "/v1/agent/jobs/claim" {
		var empty struct{}
		if d.Decode(&empty) != nil {
			http.Error(w, "invalid request", 400)
			return
		}
	} else {
		if d.Decode(&value) != nil {
			http.Error(w, "invalid result", 400)
			return
		}
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		http.Error(w, "invalid request", 400)
		return
	}
	var v any
	var err error
	if r.URL.Path == "/v1/agent/jobs/claim" {
		var job *jobs.Job
		job, err = store.ClaimJob(r.Context(), id, hash, time.Now().UTC())
		v = map[string]any{"job": job}
	} else {
		err = store.FinishJob(r.Context(), id, hash, value, time.Now().UTC())
		v = map[string]bool{"ok": true}
	}
	if err != nil {
		status := 503
		switch {
		case errors.Is(err, ErrUnauthorized):
			status = 401
		case errors.Is(err, jobs.ErrInvalid):
			status = 400
		case errors.Is(err, jobs.ErrTerminal):
			status = 409
		case errors.Is(err, jobs.ErrReportPending):
			status = 425
		}
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (c *Client) jobRequest(ctx context.Context, path string, value, result any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.origin+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.credentials.Token)
	req.Header.Set("X-Cerber-Agent", c.credentials.AgentID)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("job transport unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 409 {
		return jobs.ErrTerminal
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("job receiver HTTP %d", resp.StatusCode)
	}
	d := json.NewDecoder(io.LimitReader(resp.Body, 16384))
	d.DisallowUnknownFields()
	if err = d.Decode(result); err != nil {
		return fmt.Errorf("invalid job response")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fmt.Errorf("invalid job response")
	}
	return nil
}
func (c *Client) ClaimJob(ctx context.Context) (*jobs.Job, error) {
	var v struct {
		Job *jobs.Job `json:"job"`
	}
	err := c.jobRequest(ctx, "/v1/agent/jobs/claim", struct{}{}, &v)
	if err != nil {
		return nil, err
	}
	if v.Job != nil && (!Identifier(v.Job.ID) || v.Job.AgentID != c.credentials.AgentID || !jobs.ValidKind(v.Job.Kind) || v.Job.RefreshMetadata && v.Job.Kind != "updates" || v.Job.State != "running" || v.Job.StartedAt == nil || v.Job.ExpiresAt.IsZero()) {
		return nil, fmt.Errorf("invalid job assignment")
	}
	return v.Job, nil
}
func (c *Client) FinishJob(ctx context.Context, result jobs.Result) error {
	var v struct {
		OK bool `json:"ok"`
	}
	if err := c.jobRequest(ctx, "/v1/agent/jobs/finish", result, &v); err != nil {
		return err
	}
	if !v.OK {
		return fmt.Errorf("job result not acknowledged")
	}
	return nil
}
