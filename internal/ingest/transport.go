// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

// agentTransport identifies the machine client and shares gateway backpressure
// across events, heartbeat and job polling. Retained spool batches are retried
// by their owner; the transport never replays a request itself.
type agentTransport struct {
	base     http.RoundTripper
	once     sync.Once
	gate     chan struct{}
	next     time.Time
	cooldown time.Duration
}

func (t *agentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.once.Do(func() { t.gate = make(chan struct{}, 1) })
	select {
	case t.gate <- struct{}{}:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	defer func() { <-t.gate }()
	if wait := time.Until(t.next); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-timer.C:
		}
	}
	r := req.Clone(req.Context())
	r.Header = req.Header.Clone()
	r.Header.Set("User-Agent", "Cerber-Agent/1")
	r.Header.Set("Accept", "application/json")
	response, err := t.base.RoundTrip(r)
	t.next = time.Now().Add(100 * time.Millisecond)
	if err == nil && (response.StatusCode == http.StatusTooManyRequests) {
		delay := t.cooldown
		if delay == 0 {
			delay = 70 * time.Second
		}
		if value := response.Header.Get("Retry-After"); value != "" {
			if seconds, e := strconv.Atoi(value); e == nil && seconds > 0 && seconds <= 900 {
				if d := time.Duration(seconds) * time.Second; d > delay {
					delay = d
				}
			} else if at, e := http.ParseTime(value); e == nil {
				if d := time.Until(at); d > delay && d <= 15*time.Minute {
					delay = d
				}
			}
		}
		t.next = time.Now().Add(delay)
	}
	return response, err
}
func (t *agentTransport) CloseIdleConnections() {
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
