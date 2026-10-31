// SPDX-License-Identifier: Apache-2.0
package integrations

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"time"
)

func feedID(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func sendSMTP(ctx context.Context, m SMTP, id, subject, body string, details MailDetails) error {
	return sendSMTPWithTLS(ctx, m, id, subject, body, details, &tls.Config{ServerName: m.Host, MinVersion: tls.VersionTLS12})
}
func sendSMTPWithTLS(ctx context.Context, m SMTP, id, subject, body string, details MailDetails, cfg *tls.Config) error {
	message, e := composeMail(m, id, subject, body, details, time.Now())
	if e != nil {
		return fmt.Errorf("SMTP message rendering failed")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, e := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(m.Host, strconv.Itoa(m.Port)))
	if e != nil {
		return fmt.Errorf("SMTP connection failed")
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	var transport net.Conn = &boundedConn{Conn: conn, remaining: 1 << 20}
	if m.Security == "tls" {
		secured := tls.Client(transport, cfg)
		if e = secured.HandshakeContext(ctx); e != nil {
			return fmt.Errorf("SMTP TLS failed")
		}
		transport = secured
	}
	c, e := smtp.NewClient(transport, m.Host)
	if e != nil {
		return fmt.Errorf("SMTP greeting failed")
	}
	defer c.Close()
	if m.Security == "starttls" {
		if e = c.StartTLS(cfg); e != nil {
			return fmt.Errorf("SMTP STARTTLS failed")
		}
	} else if m.Security != "tls" {
		return ErrInvalid
	}
	if m.Username != "" {
		if e = c.Auth(smtp.PlainAuth("", m.Username, m.Password, m.Host)); e != nil {
			return fmt.Errorf("SMTP authentication failed")
		}
	}
	if e = c.Mail(m.From); e != nil {
		return fmt.Errorf("SMTP sender rejected")
	}
	for _, to := range m.To {
		if e = c.Rcpt(to); e != nil {
			return fmt.Errorf("SMTP recipient rejected")
		}
	}
	data, e := c.Data()
	if e != nil {
		return fmt.Errorf("SMTP DATA rejected")
	}
	if _, e = data.Write(message); e != nil {
		return fmt.Errorf("SMTP message write failed")
	}
	if e = data.Close(); e != nil {
		return fmt.Errorf("SMTP delivery not confirmed")
	}
	_ = c.Quit()
	return nil
}
