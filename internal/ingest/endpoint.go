// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/endpoint"
	"io"
	"net/http"
)

func (c *Client) EndpointExchange(ctx context.Context, report endpoint.Report) (endpoint.Signed, error) {
	var signed endpoint.Signed
	b, e := json.Marshal(report)
	if e != nil {
		return signed, e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", c.origin+"/v1/agent/endpoint", bytes.NewReader(b))
	if e != nil {
		return signed, e
	}
	req.Header.Set("Authorization", "Bearer "+c.credentials.Token)
	req.Header.Set("X-Cerber-Agent", c.credentials.AgentID)
	req.Header.Set("Content-Type", "application/json")
	r, e := c.http.Do(req)
	if e != nil {
		return signed, fmt.Errorf("endpoint transport unavailable")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return signed, fmt.Errorf("endpoint HTTP %d", r.StatusCode)
	}
	data, e := io.ReadAll(io.LimitReader(r.Body, 128<<20+1))
	if e != nil || len(data) > 128<<20 {
		return signed, fmt.Errorf("endpoint size limit")
	}
	if json.Unmarshal(data, &signed) != nil {
		return signed, fmt.Errorf("invalid endpoint response")
	}
	return signed, nil
}
