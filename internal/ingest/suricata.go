// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"context"
	"errors"
	"fmt"
	rules "github.com/rkislov/cerber/internal/suricatarules"
	"io"
	"net/http"
)

func receiveSuricata(w http.ResponseWriter, r *http.Request, base Receiver, id, hash string) {
	s, ok := base.(interface {
		AssignedSuricataBundle(context.Context, string, string, string) ([]byte, error)
	})
	if !ok {
		http.Error(w, "unavailable", 503)
		return
	}
	bundle := r.URL.Query().Get("id")
	if !rules.ValidID(bundle) {
		http.Error(w, "invalid bundle", 400)
		return
	}
	b, e := s.AssignedSuricataBundle(r.Context(), id, hash, bundle)
	if e != nil {
		if errors.Is(e, ErrUnauthorized) {
			http.Error(w, "unauthorized", 401)
		} else {
			http.Error(w, "bundle unavailable", 503)
		}
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(b)
}
func (c *Client) SuricataBundle(ctx context.Context, m rules.Manifest) ([]byte, error) {
	if !rules.ValidID(m.ID) {
		return nil, rules.ErrInvalid
	}
	req, e := http.NewRequestWithContext(ctx, "GET", c.origin+"/v1/agent/suricata?id="+m.ID, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+c.credentials.Token)
	req.Header.Set("X-Cerber-Agent", c.credentials.AgentID)
	res, e := c.http.Do(req)
	if e != nil {
		return nil, fmt.Errorf("rule download failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("rule download HTTP %d", res.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, rules.MaxCompressed+1))
	if e != nil || len(b) != m.CompressedBytes || len(b) > rules.MaxCompressed {
		return nil, rules.ErrInvalid
	}
	return b, nil
}
