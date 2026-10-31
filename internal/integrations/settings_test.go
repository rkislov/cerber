// SPDX-License-Identifier: Apache-2.0
package integrations

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/cerber/internal/directory"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSMTPConsoleURLValidationAndPersistence(t *testing.T) {
	for _, value := range []string{"javascript:alert(1)", "http://siem.example/admin/", "//siem.example/admin/", "https://u:secret@siem.example/", "https://siem.example/?token=secret", "https://siem.example/#fragment", "https://siem.example/\r\nBcc:bad", "https:///admin/", "https://siem.example:bad/"} {
		if validConsoleURL(value) {
			t.Fatalf("unsafe console URL accepted: %q", value)
		}
		if _, _, err := renderMail("test", "test", value, MailDetails{}); err == nil {
			t.Fatal("renderer accepted unsafe console URL")
		}
	}
	s := testStore(t)
	m := s.View().SMTP
	m.ConsoleURL = "https://siem.example:8443/admin/"
	if err := s.Save(Command{Version: s.View().Version, Scope: "smtp", SMTP: m}, "roman"); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(Command{Version: s.View().Version, Scope: "threatfox"}, "roman"); err != nil {
		t.Fatal(err)
	}
	if s.View().SMTP.ConsoleURL != m.ConsoleURL {
		t.Fatal("other settings save changed console URL")
	}
}

func TestEncryptedSecretsPreservationAndConflict(t *testing.T) {
	d := t.TempDir()
	key := filepath.Join(d, "key")
	path := filepath.Join(d, "settings")
	os.WriteFile(key, bytes.Repeat([]byte{1}, 32), 0600)
	s, e := Open(path, key)
	if e != nil {
		t.Fatal(e)
	}
	pass, auth := "smtp-secret-fixture", "threatfox-secret-fixture"
	m := SMTP{Host: "mail.example.org", Port: 587, Security: "starttls", Username: "cerber", From: "cerber@example.org", To: []string{"ib@example.org"}}
	if e = s.Save(Command{Version: 1, SMTP: m, SMTPPassword: &pass, ThreatFoxKey: &auth}, "roman"); e != nil {
		t.Fatal(e)
	}
	disk, _ := os.ReadFile(path)
	v, _ := json.Marshal(s.View())
	for _, b := range [][]byte{disk, v} {
		if bytes.Contains(b, []byte(pass)) || bytes.Contains(b, []byte(auth)) {
			t.Fatal("secret leaked")
		}
	}
	re, e := Open(path, key)
	if e != nil || !re.View().SMTPPasswordSet || !re.View().ThreatFoxKeySet {
		t.Fatal("reload", e)
	}
	if e = re.Save(Command{Version: 2, SMTP: m}, "roman"); e != nil || re.snapshot().SMTP.Password != pass || re.snapshot().ThreatFoxKey != auth {
		t.Fatal("secret preservation", e)
	}
	if !errors.Is(re.Save(Command{Version: 2, SMTP: m}, "roman"), ErrConflict) {
		t.Fatal("lost update accepted")
	}
	if e = re.Save(Command{Version: 3, SMTP: m, ClearSMTPPassword: true, ClearThreatFoxKey: true}, "roman"); e != nil || re.View().SMTPPasswordSet || re.View().ThreatFoxKeySet {
		t.Fatal("clear", e)
	}
	disk[len(disk)/2] ^= 1
	os.WriteFile(path, disk, 0600)
	if _, e = Open(path, key); e == nil {
		t.Fatal("tampered settings accepted")
	}
}
func TestValidationRejectsInjectionAndPlaintextTLS(t *testing.T) {
	for _, m := range []SMTP{{Host: "smtp://example.org", Port: 587, Security: "starttls"}, {Host: "example.org", Port: 587, Security: "none"}, {Host: "example.org", Port: 587, Security: "tls", From: "a@example.org\r\nBcc: bad@example.org"}} {
		if validate(configuration{SMTP: m}) == nil {
			t.Fatal("accepted invalid settings")
		}
	}
}
func TestThreatFoxProbeUsesHeaderAndRejectsBadResponse(t *testing.T) {
	for _, status := range []string{"ok", "illegal_auth_key"} {
		t.Run(status, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.Header.Get("Auth-Key") != "fixture" || r.URL.RawQuery != "" {
					t.Error("unsafe request")
				}
				var q map[string]string
				json.NewDecoder(r.Body).Decode(&q)
				if q["query"] != "types" {
					t.Error(q)
				}
				json.NewEncoder(w).Encode(map[string]string{"query_status": status})
			}))
			defer srv.Close()
			e := probeThreatFox(context.Background(), srv.Client(), srv.URL, "fixture")
			if (e == nil) != (status == "ok") {
				t.Fatal(e)
			}
		})
	}
}

func TestSMTPRefusesServerWithoutTLSBeforeAuth(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	done := make(chan string, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprint(conn, "220 fixture ESMTP\r\n")
		r := bufio.NewReader(conn)
		r.ReadString('\n')
		fmt.Fprint(conn, "250-fixture\r\n250 AUTH PLAIN\r\n")
		line, _ := r.ReadString('\n')
		done <- line
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	s := &Store{config: configuration{SMTP: SMTP{Host: "127.0.0.1", Port: port, Security: "starttls", Username: "fixture", Password: "secret"}}}
	if s.ProbeSMTP(context.Background()) == nil {
		t.Fatal("plaintext SMTP accepted")
	}
	if line := <-done; strings.Contains(line, "AUTH") {
		t.Fatal("credentials sent before TLS")
	}
}

func TestDirectorySettingsEncryptedIndependentAndRedacted(t *testing.T) {
	d := t.TempDir()
	key := filepath.Join(d, "key")
	path := filepath.Join(d, "settings")
	os.WriteFile(key, bytes.Repeat([]byte{7}, 32), 0600)
	s, e := Open(path, key)
	if e != nil {
		t.Fatal(e)
	}
	pass := "directory-secret-fixture"
	cfg := directory.Config{Enabled: true, URL: "ldaps://dc.example.org", BaseDN: "DC=example,DC=org", BindDN: "svc@example.org"}
	before := s.snapshot()
	if e = s.Save(Command{Version: 1, Scope: "directory", Directory: cfg, DirectoryPassword: &pass}, "roman"); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(s.snapshot().SMTP, before.SMTP) {
		t.Fatal("AD save changed SMTP")
	}
	b, _ := os.ReadFile(path)
	v, _ := json.Marshal(s.View())
	if bytes.Contains(b, []byte(pass)) || bytes.Contains(v, []byte(pass)) || !s.View().DirectoryPasswordSet {
		t.Fatal("secret leak")
	}
	s, e = Open(path, key)
	if e != nil || s.DirectoryConfig().Password != pass {
		t.Fatal("reload", e)
	}
	if e = s.Save(Command{Version: 2, Scope: "smtp", SMTP: s.View().SMTP}, "roman"); e != nil || s.DirectoryConfig().Password != pass || s.DirectoryConfig().URL != cfg.URL {
		t.Fatal("SMTP save changed AD", e)
	}
	if e = s.Save(Command{Version: 3, Scope: "directory", Directory: cfg}, "roman"); e != nil || s.DirectoryConfig().Password != pass {
		t.Fatal("empty password not preserved", e)
	}
	if e = s.Save(Command{Version: 4, Scope: "directory", Directory: cfg, ClearDirectoryPassword: true}, "roman"); e == nil {
		t.Fatal("enabled empty service password accepted")
	}
	cfg.Enabled = false
	if e = s.Save(Command{Version: 4, Scope: "directory", Directory: cfg, ClearDirectoryPassword: true}, "roman"); e != nil || s.View().DirectoryPasswordSet {
		t.Fatal("clear disabled secret", e)
	}
	if e = s.Save(Command{Version: 5, Scope: "smtp", SMTP: s.View().SMTP, Directory: cfg}, "roman"); !errors.Is(e, ErrInvalid) {
		t.Fatal("cross-scope change", e)
	}
}
