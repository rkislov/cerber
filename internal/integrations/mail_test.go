// SPDX-License-Identifier: Apache-2.0
package integrations

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSMTPVerifiedTLSMessageDelivery(t *testing.T) {
	fixture := httptest.NewTLSServer(nil)
	certificate := fixture.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	fixture.Close()
	raw, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	listener := tls.NewListener(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	defer listener.Close()
	done := make(chan string, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		fmt.Fprint(conn, "220 fixture ESMTP\r\n")
		var data strings.Builder
		for {
			line, e := r.ReadString('\n')
			if e != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"):
				fmt.Fprint(conn, "250 fixture\r\n")
			case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"):
				fmt.Fprint(conn, "250 OK\r\n")
			case strings.HasPrefix(line, "DATA"):
				fmt.Fprint(conn, "354 send\r\n")
				for {
					line, e = r.ReadString('\n')
					if e != nil {
						return
					}
					if line == ".\r\n" {
						break
					}
					data.WriteString(line)
				}
				fmt.Fprint(conn, "250 queued\r\n")
			case strings.HasPrefix(line, "QUIT"):
				fmt.Fprint(conn, "221 bye\r\n")
				done <- data.String()
				return
			default:
				return
			}
		}
	}()
	m := SMTP{Host: "127.0.0.1", Port: raw.Addr().(*net.TCPAddr).Port, Security: "tls", From: "cerber@example.org", To: []string{"ib@example.org"}}
	e = sendSMTPWithTLS(context.Background(), m, "fixture-id", "Проверка SIEM", "Сработал IOC", sampleMailDetails(), &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12})
	if e != nil {
		t.Fatal(e)
	}
	select {
	case message := <-done:
		bodies := decodeMail(t, []byte(message), "Проверка SIEM")
		if !strings.Contains(bodies[1], "Серия неудачных входов") || !strings.Contains(bodies[0], "auth.failed_burst") {
			t.Fatal("SMTP lost HTML/text alternatives")
		}
		if !strings.Contains(message, "Message-ID:") || !strings.Contains(message, "Content-Transfer-Encoding: base64") {
			t.Fatal(message)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mail not received")
	}
}

type fixtureNotifications struct{}

func (fixtureNotifications) NotificationBatch(context.Context, int64) ([]Notification, error) {
	return []Notification{{Sequence: 1, ID: "fixture", Subject: "test", Body: "fixture", Details: sampleMailDetails()}}, nil
}
func TestMailOutboxSurvivesRestartAndDeduplicates(t *testing.T) {
	s := testStore(t)
	p := filepath.Join(t.TempDir(), "runtime.db")
	w, e := OpenWorker(s, p, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if e = w.enqueue(ctx, "alerts", fixtureNotifications{}); e != nil {
			t.Fatal(e)
		}
	}
	if w.Status(ctx).Pending != 1 {
		t.Fatal(w.Status(ctx))
	}
	w.Close()
	w, e = OpenWorker(s, p, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	if w.Status(ctx).Pending != 1 {
		t.Fatal("lost outbox")
	}
}
