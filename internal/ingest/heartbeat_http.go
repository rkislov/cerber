// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

func receiveHeartbeat(w http.ResponseWriter, r *http.Request, store Receiver, id, hash string) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxHeartbeatBytes)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var h Heartbeat
	err := decoder.Decode(&h)
	if err == nil {
		var extra any
		if next := decoder.Decode(&extra); next != io.EOF {
			if next != nil {
				err = next
			} else {
				err = fmt.Errorf("trailing JSON")
			}
		}
	}
	if err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			http.Error(w, "heartbeat too large", 413)
		} else {
			http.Error(w, "invalid heartbeat JSON", 400)
		}
		return
	}
	if h.AgentID != id {
		http.Error(w, "agent identity mismatch", 403)
		return
	}
	if h.Validate() != nil {
		http.Error(w, "invalid heartbeat", 400)
		return
	}
	receipt, err := store.AcceptHeartbeat(r.Context(), id, hash, h)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			http.Error(w, "unauthorized", 401)
		} else {
			http.Error(w, "heartbeat could not be committed", 503)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(receipt)
}
func (c *Client) Heartbeat(ctx context.Context, h Heartbeat) (HeartbeatReceipt, error) {
	var receipt HeartbeatReceipt
	if h.AgentID != c.credentials.AgentID {
		return receipt, fmt.Errorf("heartbeat belongs to another agent")
	}
	if err := h.Validate(); err != nil {
		return receipt, err
	}
	data, err := json.Marshal(h)
	if err != nil {
		return receipt, err
	}
	if int64(len(data)) > MaxHeartbeatBytes {
		return receipt, fmt.Errorf("heartbeat too large")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/v1/agent/heartbeat", bytes.NewReader(data))
	if err != nil {
		return receipt, err
	}
	req.Header.Set("Authorization", "Bearer "+c.credentials.Token)
	req.Header.Set("X-Cerber-Agent", c.credentials.AgentID)
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return receipt, fmt.Errorf("heartbeat delivery failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return receipt, fmt.Errorf("heartbeat returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 65537))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&receipt); err != nil {
		return receipt, fmt.Errorf("invalid heartbeat receipt")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || receipt.AgentID != h.AgentID || !receipt.ObservedAt.Equal(h.ObservedAt) || receipt.ReceivedAt.IsZero() {
		return receipt, fmt.Errorf("heartbeat receipt mismatch")
	}
	return receipt, nil
}
