// SPDX-License-Identifier: Apache-2.0
package integrations

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var ErrInvalid = errors.New("invalid integration settings")
var ErrConflict = errors.New("settings changed; reload current version")

type SMTP struct {
	Enabled  bool     `json:"enabled"`
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Security string   `json:"security"`
	Username string   `json:"username"`
	Password string   `json:"password,omitempty"`
	From     string   `json:"from"`
	To       []string `json:"to"`
}
type Change struct {
	At      time.Time `json:"at"`
	Actor   string    `json:"actor"`
	Version int64     `json:"version"`
	Fields  []string  `json:"fields"`
}
type configuration struct {
	ThreatFoxEnabled bool     `json:"threatfox_enabled"`
	Version          int64    `json:"version"`
	SMTP             SMTP     `json:"smtp"`
	ThreatFoxKey     string   `json:"threatfox_key,omitempty"`
	History          []Change `json:"history"`
}
type View struct {
	ThreatFoxEnabled bool     `json:"threatfox_enabled"`
	Configured       bool     `json:"configured"`
	Version          int64    `json:"version"`
	SMTP             SMTP     `json:"smtp"`
	SMTPPasswordSet  bool     `json:"smtp_password_set"`
	ThreatFoxKeySet  bool     `json:"threatfox_key_set"`
	History          []Change `json:"history"`
}
type Command struct {
	Scope             string  `json:"scope,omitempty"`
	ThreatFoxEnabled  *bool   `json:"threatfox_enabled,omitempty"`
	Version           int64   `json:"version"`
	SMTP              SMTP    `json:"smtp"`
	SMTPPassword      *string `json:"smtp_password,omitempty"`
	ClearSMTPPassword bool    `json:"clear_smtp_password"`
	ThreatFoxKey      *string `json:"threatfox_key,omitempty"`
	ClearThreatFoxKey bool    `json:"clear_threatfox_key"`
}
type sealed struct {
	Schema     int    `json:"schema"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}
type Store struct {
	mu     sync.Mutex
	path   string
	aead   cipher.AEAD
	config configuration
}

func Open(path, keyPath string) (*Store, error) {
	if !filepath.IsAbs(path) || !filepath.IsAbs(keyPath) || path == keyPath {
		return nil, ErrInvalid
	}
	for _, p := range []string{path, keyPath} {
		if st, e := os.Lstat(p); e == nil && !st.Mode().IsRegular() {
			return nil, ErrInvalid
		} else if e != nil && !os.IsNotExist(e) {
			return nil, e
		}
	}
	key, e := os.ReadFile(keyPath)
	if e != nil {
		return nil, e
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("settings key must contain exactly 32 random bytes")
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	s := &Store{path: path, aead: aead, config: configuration{Version: 1, SMTP: SMTP{Port: 587, Security: "starttls", To: []string{}}, History: []Change{}}}
	file, e := os.Open(path)
	if os.IsNotExist(e) {
		return s, nil
	}
	if e != nil {
		return nil, e
	}
	defer file.Close()
	b, e := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if e != nil || len(b) > 1<<20 {
		return nil, ErrInvalid
	}
	var disk sealed
	if json.Unmarshal(b, &disk) != nil || disk.Schema != 1 || len(disk.Nonce) != aead.NonceSize() {
		return nil, ErrInvalid
	}
	data, e := aead.Open(nil, disk.Nonce, disk.Ciphertext, []byte("cerber/integrations/1"))
	if e != nil {
		return nil, fmt.Errorf("integration settings could not be decrypted")
	}
	if json.Unmarshal(data, &s.config) != nil || s.config.Version < 1 || validate(s.config) != nil {
		return nil, ErrInvalid
	}
	return s, nil
}
func (s *Store) View() View {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := View{ThreatFoxEnabled: s.config.ThreatFoxEnabled, Configured: true, Version: s.config.Version, SMTP: s.config.SMTP, SMTPPasswordSet: s.config.SMTP.Password != "", ThreatFoxKeySet: s.config.ThreatFoxKey != "", History: append([]Change{}, s.config.History...)}
	v.SMTP.Password = ""
	v.SMTP.To = append([]string{}, v.SMTP.To...)
	return v
}
func validate(c configuration) error {
	m := c.SMTP
	if len(m.Host) > 253 || strings.ContainsAny(m.Host, "\x00\r\n /\\:@") || len(m.Username) > 320 || len(m.Password) > 4096 || strings.ContainsAny(m.Username+m.Password, "\x00\r\n") || len(m.To) > 20 {
		return ErrInvalid
	}
	if m.Host != "" {
		if net.ParseIP(m.Host) == nil {
			for _, part := range strings.Split(m.Host, ".") {
				if len(part) == 0 || len(part) > 63 || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
					return ErrInvalid
				}
				for _, r := range part {
					if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
						return ErrInvalid
					}
				}
			}
		}
		if m.Port < 1 || m.Port > 65535 {
			return ErrInvalid
		}
	}
	if m.Security != "starttls" && m.Security != "tls" {
		return ErrInvalid
	}
	for _, a := range append(append([]string{}, m.To...), m.From) {
		if a == "" {
			continue
		}
		if len(a) > 320 || strings.ContainsAny(a, "\x00\r\n") {
			return ErrInvalid
		}
		v, e := mail.ParseAddress(a)
		if e != nil || v.Address != a {
			return ErrInvalid
		}
	}
	if m.Enabled && (m.Host == "" || m.From == "" || len(m.To) == 0) {
		return ErrInvalid
	}
	if c.ThreatFoxEnabled && c.ThreatFoxKey == "" {
		return ErrInvalid
	}
	if m.Password != "" && m.Username == "" {
		return ErrInvalid
	}
	if len(c.ThreatFoxKey) > 512 {
		return ErrInvalid
	}
	for _, r := range c.ThreatFoxKey {
		if r < 33 || r > 126 {
			return ErrInvalid
		}
	}
	return nil
}
func (s *Store) Save(c Command, actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.Version != s.config.Version {
		return ErrConflict
	}
	if actor == "" || len(actor) > 64 || c.SMTP.Password != "" || c.SMTPPassword != nil && c.ClearSMTPPassword || c.ThreatFoxKey != nil && c.ClearThreatFoxKey {
		return ErrInvalid
	}
	next := s.config
	next.Version++
	if c.Scope != "" && c.Scope != "smtp" && c.Scope != "threatfox" {
		return ErrInvalid
	}
	if c.Scope == "smtp" && (c.ThreatFoxKey != nil || c.ClearThreatFoxKey || c.ThreatFoxEnabled != nil) {
		return ErrInvalid
	}
	if c.Scope == "threatfox" && (c.SMTPPassword != nil || c.ClearSMTPPassword) {
		return ErrInvalid
	}
	if c.Scope != "threatfox" {
		next.SMTP = c.SMTP
		next.SMTP.To = append([]string{}, c.SMTP.To...)
		next.SMTP.Password = s.config.SMTP.Password
		if c.SMTPPassword != nil {
			next.SMTP.Password = *c.SMTPPassword
		}
		if c.ClearSMTPPassword {
			next.SMTP.Password = ""
		}
	}
	if c.ThreatFoxEnabled != nil {
		next.ThreatFoxEnabled = *c.ThreatFoxEnabled
	}
	if c.ThreatFoxKey != nil {
		next.ThreatFoxKey = *c.ThreatFoxKey
	}
	if c.ClearThreatFoxKey {
		next.ThreatFoxKey = ""
	}
	if e := validate(next); e != nil {
		return e
	}
	fields := []string{}
	if c.Scope != "threatfox" {
		fields = append(fields, "smtp")
	}
	if c.Scope == "threatfox" || c.ThreatFoxKey != nil || c.ClearThreatFoxKey {
		fields = append(fields, "threatfox_key")
	}
	next.History = append(append([]Change{}, s.config.History...), Change{At: time.Now().UTC(), Actor: actor, Version: next.Version, Fields: fields})
	if len(next.History) > 1000 {
		next.History = next.History[len(next.History)-1000:]
	}
	data, e := json.Marshal(next)
	if e != nil {
		return e
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	encrypted := s.aead.Seal(nil, nonce, data, []byte("cerber/integrations/1"))
	data, e = json.Marshal(sealed{1, nonce, encrypted})
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".settings-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(data); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = os.Rename(name, s.path); e != nil {
		return e
	}
	s.config = next
	return nil
}
func (s *Store) snapshot() configuration { s.mu.Lock(); defer s.mu.Unlock(); return s.config }
