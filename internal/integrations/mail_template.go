// SPDX-License-Identifier: Apache-2.0
package integrations

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"fmt"
	"html"
	"html/template"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"strings"
	"time"
)

// MailDetails is persisted with the outbox so retries retain the event context.
// Fields are text only; no event content is accepted as HTML or as a link.
type MailDetails struct {
	Title      string      `json:"title,omitempty"`
	Kind       string      `json:"kind,omitempty"`
	Severity   string      `json:"severity,omitempty"`
	Summary    string      `json:"summary,omitempty"`
	OccurredAt time.Time   `json:"occurred_at,omitempty"`
	Fields     []MailField `json:"fields,omitempty"`
}

type MailField struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Code  bool   `json:"code,omitempty"`
}

//go:embed mail.html
var mailHTML string

var notificationTemplate = template.Must(template.New("notification").Funcs(template.FuncMap{
	// html/template removes literal comments. These constants retain Outlook's
	// fixed-width wrapper without treating any event content as trusted markup.
	"outlookStart": func() template.HTML {
		return `<!--[if mso]><table role="presentation" width="640" cellspacing="0" cellpadding="0" border="0"><tr><td><![endif]-->`
	},
	"outlookEnd": func() template.HTML { return `<!--[if mso]></td></tr></table><![endif]-->` },
	// Add wrapping opportunities without changing the copied identifier.
	// Every chunk is escaped before adding this fixed, trusted markup.
	"wrapID": func(value string) template.HTML {
		var b strings.Builder
		for i, r := range []rune(value) {
			if i > 0 && i%16 == 0 {
				b.WriteString("<wbr>")
			}
			b.WriteString(html.EscapeString(string(r)))
		}
		return template.HTML(b.String())
	},
}).Parse(mailHTML))

type mailView struct {
	Title, Category, Severity, Summary, Color, Tint, ConsoleURL string
	Fields                                                      []MailField
}

// Recognize only the text layouts emitted by older Cerber versions. This is
// presentation-only: values remain escaped text, with no inferred severity,
// timestamp or URL. Unrecognized lines are preserved in the summary.
func legacyMailDetails(subject, body string) MailDetails {
	d := MailDetails{Title: subject, Summary: body}
	switch {
	case strings.HasPrefix(subject, "Срабатывание SIEM: "):
		title, rest, ok := strings.Cut(body, "\n")
		if !ok || title == "" {
			return d
		}
		d.Title, d.Kind, body = title, "detection", rest
		d.Fields = []MailField{{Label: "Правило", Value: strings.TrimPrefix(subject, "Срабатывание SIEM: ")}}
	case strings.HasPrefix(subject, "Предупреждение SIEM: "):
		d.Title = strings.TrimPrefix(subject, "Предупреждение SIEM: ")
	case strings.HasPrefix(subject, "Восстановление SIEM: "):
		d.Title, d.Kind = strings.TrimPrefix(subject, "Восстановление SIEM: "), "recovery"
	default:
		return d
	}
	var remaining []string
	for _, line := range strings.Split(body, "\n") {
		label, value, ok := strings.Cut(line, ": ")
		if ok && (label == "Агент" || label == "ID срабатывания" || label == "ID предупреждения" || label == "ID") {
			d.Fields = append(d.Fields, MailField{Label: label, Value: value, Code: true})
		} else {
			remaining = append(remaining, line)
		}
	}
	d.Summary = strings.Join(remaining, "\n")
	return d
}

func renderMail(subject, body, consoleURL string, details MailDetails) (string, string, error) {
	if !validConsoleURL(consoleURL) {
		return "", "", ErrInvalid
	}
	if details.Title == "" {
		details = legacyMailDetails(subject, body)
	}
	v := mailView{Title: details.Title, Summary: details.Summary, ConsoleURL: consoleURL,
		Category: "Уведомление SIEM", Color: "#52647a", Tint: "#edf1f5"}
	switch details.Kind {
	case "detection":
		v.Category = "Срабатывание корреляции"
	case "alert":
		v.Category = "Состояние инфраструктуры"
	case "health":
		v.Category = "Состояние SIEM"
	case "recovery":
		v.Category, v.Severity, v.Color, v.Tint = "Состояние SIEM", "Восстановлено", "#137565", "#e8f6f1"
	}
	if details.Kind != "recovery" {
		switch details.Severity {
		case "critical":
			v.Severity, v.Color, v.Tint = "Критическая", "#a82038", "#fcecf0"
		case "high":
			v.Severity, v.Color, v.Tint = "Высокая", "#b43a23", "#fceee9"
		case "medium":
			v.Severity, v.Color, v.Tint = "Средняя", "#946000", "#fff4d9"
		case "warning":
			v.Severity, v.Color, v.Tint = "Предупреждение", "#946000", "#fff4d9"
		case "low":
			v.Severity, v.Color, v.Tint = "Низкая", "#137565", "#e8f6f1"
		case "info", "informational":
			v.Severity = "Информация"
		}
	}
	if !details.OccurredAt.IsZero() {
		v.Fields = append(v.Fields, MailField{Label: "Время (UTC)", Value: details.OccurredAt.UTC().Format("02.01.2006 · 15:04:05")})
	}
	for _, f := range details.Fields {
		if f.Value != "" {
			v.Fields = append(v.Fields, f)
		}
	}
	var rendered bytes.Buffer
	if err := notificationTemplate.Execute(&rendered, v); err != nil {
		return "", "", err
	}
	var plain strings.Builder
	fmt.Fprintf(&plain, "CERBER · %s\n", v.Category)
	if v.Severity != "" {
		fmt.Fprintf(&plain, "Критичность / статус: %s\n", v.Severity)
	}
	fmt.Fprintf(&plain, "\n%s\n", v.Title)
	if v.Summary != "" {
		fmt.Fprintf(&plain, "\n%s\n", v.Summary)
	}
	for _, f := range v.Fields {
		fmt.Fprintf(&plain, "\n%s: %s", f.Label, f.Value)
	}
	plain.WriteString("\n\nПодробности и исходные события доступны в консоли SIEM.\n")
	if consoleURL != "" {
		fmt.Fprintf(&plain, "Открыть SIEM: %s\n", consoleURL)
	}
	plain.WriteString("\nАвтоматическое уведомление CERBER.\n")
	return plain.String(), rendered.String(), nil
}

func composeMail(m SMTP, id, subject, body string, details MailDetails, sentAt time.Time) ([]byte, error) {
	if validate(configuration{SMTP: m}) != nil || strings.ContainsAny(subject, "\r\n\x00") {
		return nil, ErrInvalid
	}
	plain, rich, err := renderMail(subject, body, m.ConsoleURL, details)
	if err != nil {
		return nil, err
	}
	var message bytes.Buffer
	parts := multipart.NewWriter(&message)
	fmt.Fprintf(&message, "From: %s\r\nTo: %s\r\nDate: %s\r\nMessage-ID: <%s@cerber.local>\r\nSubject:\r\n %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative;\r\n boundary=%q\r\n\r\n",
		(&mail.Address{Name: "CERBER SIEM", Address: m.From}).String(), strings.Join(m.To, ",\r\n "), sentAt.UTC().Format(time.RFC1123Z), feedID([]byte(id)),
		strings.ReplaceAll(mime.BEncoding.Encode("UTF-8", subject), " ", "\r\n "), parts.Boundary())
	for _, part := range []struct{ kind, content string }{{"text/plain", plain}, {"text/html", rich}} {
		h := textproto.MIMEHeader{}
		h.Set("Content-Type", part.kind+"; charset=UTF-8")
		h.Set("Content-Transfer-Encoding", "base64")
		writer, err := parts.CreatePart(h)
		if err != nil {
			return nil, err
		}
		encoded := base64.StdEncoding.EncodeToString([]byte(part.content))
		for len(encoded) > 0 {
			n := min(76, len(encoded))
			if _, err = fmt.Fprint(writer, encoded[:n]+"\r\n"); err != nil {
				return nil, err
			}
			encoded = encoded[n:]
		}
	}
	if err = parts.Close(); err != nil {
		return nil, err
	}
	return message.Bytes(), nil
}
