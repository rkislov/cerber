// SPDX-License-Identifier: Apache-2.0
package integrations

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"time"
)

const threatFoxURL = "https://threatfox-api.abuse.ch/api/v1/"

func (s *Store) ProbeThreatFox(ctx context.Context) error {
	key := s.snapshot().ThreatFoxKey
	if key == "" {
		return ErrInvalid
	}
	return probeThreatFox(ctx, &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, threatFoxURL, key)
}
func probeThreatFox(ctx context.Context, client *http.Client, url, key string) error {
	req, e := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBufferString(`{"query":"types"}`))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Auth-Key", key)
	r, e := client.Do(req)
	if e != nil {
		return fmt.Errorf("ThreatFox connection failed")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return fmt.Errorf("ThreatFox returned HTTP %d", r.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if e != nil || len(b) > 1<<20 {
		return fmt.Errorf("ThreatFox response rejected")
	}
	var v struct {
		Status string `json:"query_status"`
	}
	if json.Unmarshal(b, &v) != nil || v.Status != "ok" {
		return fmt.Errorf("ThreatFox rejected the API key or request")
	}
	return nil
}

type boundedConn struct {
	net.Conn
	remaining int64
}

func (c *boundedConn) Read(b []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, fmt.Errorf("SMTP response limit")
	}
	if int64(len(b)) > c.remaining {
		b = b[:c.remaining]
	}
	n, e := c.Conn.Read(b)
	c.remaining -= int64(n)
	return n, e
}
func (s *Store) ProbeSMTP(ctx context.Context) error {
	m := s.snapshot().SMTP
	if m.Host == "" {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, e := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(m.Host, strconv.Itoa(m.Port)))
	if e != nil {
		return fmt.Errorf("SMTP connection failed")
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	tlsConfig := &tls.Config{ServerName: m.Host, MinVersion: tls.VersionTLS12}
	var transport net.Conn = &boundedConn{Conn: conn, remaining: 1 << 20}
	if m.Security == "tls" {
		secured := tls.Client(transport, tlsConfig)
		if e = secured.HandshakeContext(ctx); e != nil {
			return fmt.Errorf("SMTP TLS verification failed")
		}
		transport = secured
	}
	client, e := smtp.NewClient(transport, m.Host)
	if e != nil {
		return fmt.Errorf("SMTP greeting failed")
	}
	defer client.Close()
	if m.Security == "starttls" {
		if e = client.StartTLS(tlsConfig); e != nil {
			return fmt.Errorf("SMTP STARTTLS verification failed")
		}
	}
	if m.Username != "" {
		if e = client.Auth(smtp.PlainAuth("", m.Username, m.Password, m.Host)); e != nil {
			return fmt.Errorf("SMTP authentication rejected")
		}
	}
	_ = client.Quit()
	return nil // Connection/auth only. Does not send MAIL/RCPT/DATA.
}
