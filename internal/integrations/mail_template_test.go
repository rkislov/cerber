// SPDX-License-Identifier: Apache-2.0
package integrations

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleMailDetails() MailDetails {
	return MailDetails{Title: "Серия неудачных входов", Kind: "detection", Severity: "high",
		OccurredAt: time.Date(2026, 10, 31, 10, 42, 23, 0, time.UTC),
		Fields: []MailField{
			{Label: "Правило", Value: "auth.failed_burst"}, {Label: "IP источника", Value: "192.0.2.45"},
			{Label: "Агент", Value: "7c4af20e63ba4181a2f774dc2389a1b0", Code: true},
			{Label: "ID срабатывания", Value: strings.Repeat("de051635a62111f4", 4), Code: true},
		}}
}

func decodeMail(t *testing.T, message []byte, subject string) []string {
	t.Helper()
	m, err := mail.ReadMessage(bytes.NewReader(message))
	if err != nil {
		t.Fatal(err)
	}
	decodedSubject, err := new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject"))
	if err != nil || decodedSubject != subject {
		t.Fatalf("subject %q: %v", decodedSubject, err)
	}
	kind, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil || kind != "multipart/alternative" || params["boundary"] == "" {
		t.Fatalf("not multipart/alternative: %s, %v", kind, err)
	}
	reader := multipart.NewReader(m.Body, params["boundary"])
	var bodies []string
	for _, expected := range []string{"text/plain", "text/html"} {
		part, err := reader.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		kind, params, err = mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil || kind != expected || params["charset"] != "UTF-8" || part.Header.Get("Content-Transfer-Encoding") != "base64" {
			t.Fatal("invalid alternative", part.Header)
		}
		b, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, part))
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, string(b))
	}
	if _, err := reader.NextPart(); err != io.EOF {
		t.Fatal("unexpected extra MIME part", err)
	}
	for _, line := range strings.Split(string(message), "\r\n") {
		if len(line) > 998 {
			t.Fatal("SMTP line exceeds the maximum length")
		}
	}
	return bodies
}

func TestMailAlternativesAndEscaping(t *testing.T) {
	d := sampleMailDetails()
	d.Title = `<img src=x onerror="alert(1)"> & тест`
	d.Fields = append(d.Fields, MailField{Label: `<script>label</script>`, Value: `<svg onload="alert(1)">`}, MailField{Label: "ID", Value: `<script>alert('test')</script>`, Code: true})
	subject := strings.Repeat("Срабатывание SIEM: проверка ", 8)
	m := SMTP{Security: "tls", From: "cerber@example.org", To: []string{"soc@example.org"}, ConsoleURL: "https://siem.example.org/admin/"}
	raw, err := composeMail(m, "fixture", subject, "legacy body", d, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bodies := decodeMail(t, raw, subject)
	if !strings.Contains(bodies[0], d.Title) || !strings.Contains(bodies[0], d.Fields[3].Value) || !strings.Contains(bodies[0], m.ConsoleURL) {
		t.Fatal("plain text lost title, full ID or link")
	}
	for _, unsafe := range []string{"<img", "<svg", "<script", "#ZgotmplZ"} {
		if strings.Contains(bodies[1], unsafe) {
			t.Fatal("unsafe markup or rejected template value", unsafe)
		}
	}
	if !strings.Contains(bodies[1], "&lt;img") || !strings.Contains(bodies[1], "<wbr>") || !strings.Contains(bodies[1], `href="https://siem.example.org/admin/"`) {
		t.Fatal("missing escaped content, wrapping or console link")
	}
	if !strings.Contains(bodies[1], "<!--[if mso]>") {
		t.Fatal("Outlook width wrapper stripped by template renderer")
	}
	if _, err = composeMail(m, "fixture", "subject\r\nBcc: other@example.org", "", d, time.Now()); err == nil {
		t.Fatal("header injection accepted")
	}
}

func TestMailVariantsAndPreview(t *testing.T) {
	for _, kind := range []string{"detection", "alert", "health", "recovery", "legacy"} {
		t.Run(kind, func(t *testing.T) {
			d := sampleMailDetails()
			d.Kind = kind
			switch kind {
			case "alert":
				d.Title, d.Severity = "Потеря связи с агентом", "critical"
				d.Summary = "Агент не отправлял heartbeat более 15 минут."
			case "health":
				d.Title, d.Severity = "Недостаточно свободного места", "warning"
				d.Summary = "На разделе хранилища осталось 8% свободного места."
			case "recovery":
				d.Title, d.Summary, d.Fields = "Обработка событий восстановлена", "Условие предупреждения устранено.", nil
			case "legacy":
				d = MailDetails{}
			}
			plain, rich, err := renderMail("Срабатывание SIEM: auth.failed_burst", "Серия неудачных входов\nАгент: 7c4af20e63ba4181a2f774dc2389a1b0\nID срабатывания: "+strings.Repeat("abcdef01", 8), "https://siem.example.org/admin/", d)
			if err != nil || !strings.Contains(plain, "Открыть SIEM") || strings.Contains(rich, "ZgotmplZ") {
				t.Fatal("invalid template", err)
			}
			if kind == "recovery" && (!strings.Contains(rich, "Восстановлено") || strings.Contains(rich, "Высокая")) {
				t.Fatal("recovery shown as an active alert")
			}
			// Optional local visual QA artifacts; never sends an email.
			if dir := os.Getenv("CERBER_MAIL_PREVIEW_DIR"); dir != "" {
				if err = os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, kind+".html"), []byte(rich), 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	_, rich, err := renderMail("Сообщение", "Исходное сообщение", "", MailDetails{Severity: "not-a-severity"})
	if err != nil || strings.Contains(rich, "href=") || strings.Contains(rich, "Критическая") || !strings.Contains(rich, "Исходное сообщение") {
		t.Fatal("unconfigured link or severity was invented", err)
	}
}

func TestLegacyMailRetainsTextWithoutInventingContext(t *testing.T) {
	body := "Серия неудачных входов\nАгент: <script>not HTML</script>\nID срабатывания: " + strings.Repeat("f", 64) + "\nДополнительная строка: текст"
	d := legacyMailDetails("Срабатывание SIEM: auth.failed_burst", body)
	if d.Title != "Серия неудачных входов" || d.Severity != "" || !d.OccurredAt.IsZero() || len(d.Fields) != 3 || d.Summary != "Дополнительная строка: текст" {
		t.Fatal("incorrect legacy conversion", d)
	}
	plain, rich, err := renderMail("Срабатывание SIEM: auth.failed_burst", body, "", MailDetails{})
	if err != nil || !strings.Contains(plain, strings.Repeat("f", 64)) || !strings.Contains(plain, "<script>not HTML</script>") || strings.Contains(rich, "<script>") || strings.Contains(rich, "Высокая") {
		t.Fatal("unsafe or lossy legacy rendering", err)
	}
	unknown := legacyMailDetails("Неизвестный формат", body)
	if unknown.Summary != body || len(unknown.Fields) != 0 {
		t.Fatal("unknown format changed")
	}
}

func TestMailLegacyOutboxMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE mail(id TEXT PRIMARY KEY,subject TEXT NOT NULL,body TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,next_at TEXT NOT NULL DEFAULT '',sent_at TEXT);
	INSERT INTO mail(id,subject,body,attempts,next_at) VALUES('old','Старое предупреждение','ID: legacy',3,'2026-01-01T00:00:00Z');
	INSERT INTO mail(id,subject,body,state,sent_at) VALUES('sent','Уже отправлено','done','sent','2026-01-01T00:00:00Z');`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		w, err := OpenWorker(testStore(t), path, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		var subject, body, details, next string
		var attempts int
		err = w.db.QueryRow("SELECT subject,body,details,attempts,next_at FROM mail WHERE id='old'").Scan(&subject, &body, &details, &attempts, &next)
		if err != nil || details != "" || attempts != 3 || next != "2026-01-01T00:00:00Z" || w.Status(context.Background()).Sent != 1 {
			t.Fatal("migration changed pending/sent state", err)
		}
		_, rich, err := renderMail(subject, body, "", MailDetails{})
		if err != nil || !strings.Contains(rich, "ID: legacy") {
			t.Fatal("legacy message cannot render", err)
		}
		if err = w.enqueue(context.Background(), "alerts", fixtureNotifications{}); err != nil {
			t.Fatal(err)
		}
		if err = w.db.QueryRow("SELECT details FROM mail WHERE id='alerts:fixture'").Scan(&details); err != nil {
			t.Fatal(err)
		}
		var d MailDetails
		if json.Unmarshal([]byte(details), &d) != nil || d.Title != sampleMailDetails().Title || len(d.Fields) != 4 {
			t.Fatal("structured context lost in outbox")
		}
		if w.Status(context.Background()).Pending != 2 {
			t.Fatal("outbox duplicated or lost pending mail")
		}
		w.Close()
	}
}
