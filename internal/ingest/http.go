// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/cerber/internal/domain"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var ErrUnauthorized = errors.New("agent unauthorized")

type Receiver interface {
	JobReceiver
	AgentBinding(context.Context, string, string) (string, error)
	AcceptReport(context.Context, string, string, Report) (Receipt, error)
	AcceptHeartbeat(context.Context, string, string, Heartbeat) (HeartbeatReceipt, error)
}

func NewHandler(store Receiver) http.Handler {
	slots := make(chan struct{}, 4)
	heartbeatSlots := make(chan struct{}, 4)
	jobSlots := make(chan struct{}, 4)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		isHeartbeat := r.URL.Path == "/v1/agent/heartbeat"
		isJob := r.URL.Path == "/v1/agent/jobs/claim" || r.URL.Path == "/v1/agent/jobs/finish"
		if r.URL.Path != "/v1/agent/reports" && !isHeartbeat && !isJob {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", 405)
			return
		}
		id := r.Header.Get("X-Cerber-Agent")
		authorization := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authorization, "Bearer ")
		if !Identifier(id) || token == authorization || len(token) < 32 || len(token) > 512 {
			http.Error(w, "unauthorized", 401)
			return
		}
		hash := Hash([]byte(token))
		if _, err := store.AgentBinding(r.Context(), id, hash); err != nil {
			if errors.Is(err, ErrUnauthorized) {
				http.Error(w, "unauthorized", 401)
			} else {
				http.Error(w, "storage unavailable", 503)
			}
			return
		}
		admission := slots
		if isHeartbeat {
			admission = heartbeatSlots
		} else if isJob {
			admission = jobSlots
		}
		select {
		case admission <- struct{}{}:
			defer func() { <-admission }()
		default:
			w.Header().Set("Retry-After", "30")
			http.Error(w, "receiver busy", 429)
			return
		}
		content, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || content != "application/json" {
			http.Error(w, "application/json required", 415)
			return
		}
		if isJob {
			receiveJob(w, r, store, id, hash)
			return
		}
		if isHeartbeat {
			receiveHeartbeat(w, r, store, id, hash)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxReportBytes)
		defer r.Body.Close()
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var report Report
		if err = decoder.Decode(&report); err == nil {
			var extra any
			if trailingErr := decoder.Decode(&extra); trailingErr != io.EOF {
				if trailingErr != nil {
					err = trailingErr
				} else {
					err = fmt.Errorf("trailing data")
				}
			}
		}
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "report too large", 413)
			} else {
				http.Error(w, "invalid report JSON", 400)
			}
			return
		}
		if report.AgentID != id {
			http.Error(w, "agent identity mismatch", 403)
			return
		}
		if err = report.Validate(); err != nil {
			http.Error(w, "invalid inventory or checks", 400)
			return
		}
		receipt, err := store.AcceptReport(r.Context(), id, hash, report)
		if err != nil {
			switch {
			case errors.Is(err, ErrUnauthorized):
				http.Error(w, "unauthorized", 401)
			case errors.Is(err, domain.ErrConflict):
				http.Error(w, "immutable report or record conflicts with stored data", 409)
			default:
				http.Error(w, "report could not be committed", 503)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(receipt)
	})
}

type Credentials struct {
	AgentID string `json:"agent_id"`
	Token   string `json:"token"`
}

func (c Credentials) Validate() error {
	if !Identifier(c.AgentID) || len(c.Token) != 64 {
		return fmt.Errorf("invalid agent credentials")
	}
	for _, v := range c.Token {
		if !(v >= '0' && v <= '9' || v >= 'a' && v <= 'f') {
			return fmt.Errorf("invalid agent token")
		}
	}
	return nil
}

type Client struct {
	origin      string
	credentials Credentials
	http        *http.Client
}

func NewClient(origin string, c Credentials, caPEM []byte) (*Client, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("server must be an HTTPS origin")
	}
	if u.Scheme != "https" {
		ip, e := netip.ParseAddr(u.Hostname())
		if u.Scheme != "http" || e != nil || !ip.Unmap().IsLoopback() {
			return nil, fmt.Errorf("HTTP allowed only for literal loopback; use HTTPS for network delivery")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caPEM) > 0 {
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("CA file contains no certificates")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	return &Client{origin: strings.TrimRight(origin, "/"), credentials: c, http: &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) Send(ctx context.Context, report Report) (Receipt, error) {
	var receipt Receipt
	if report.AgentID != c.credentials.AgentID {
		return receipt, fmt.Errorf("queued report belongs to another agent")
	}
	if err := report.Validate(); err != nil {
		return receipt, err
	}
	data, err := json.Marshal(report)
	if err != nil {
		return receipt, err
	}
	if int64(len(data)) > MaxReportBytes {
		return receipt, fmt.Errorf("report too large")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/v1/agent/reports", bytes.NewReader(data))
	if err != nil {
		return receipt, err
	}
	req.Header.Set("Authorization", "Bearer "+c.credentials.Token)
	req.Header.Set("X-Cerber-Agent", c.credentials.AgentID)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return receipt, fmt.Errorf("report delivery failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return receipt, fmt.Errorf("SIEM returned HTTP %d; report retained for retry", resp.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 8192))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&receipt); err != nil {
		return receipt, fmt.Errorf("invalid SIEM receipt")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || receipt.ReportID != report.ID || receipt.AgentID != report.AgentID || receipt.SnapshotID != RemoteID(report.AgentID, "inventory", report.Snapshot.ID) || receipt.ReceivedAt.IsZero() {
		return receipt, fmt.Errorf("SIEM receipt does not acknowledge this report")
	}
	return receipt, nil
}
