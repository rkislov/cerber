// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

func ValidKey(token string) bool {
	if len(token) != 64 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}
func ReadKey(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var v struct {
		Token string `json:"token"`
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return "", err
	}
	if len(data) > 4096 {
		return "", fmt.Errorf("administrator key file exceeds 4 KiB")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || !ValidKey(v.Token) {
		return "", fmt.Errorf("invalid administrator key file")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return "", fmt.Errorf("invalid administrator key file")
	}
	return v.Token, nil
}
func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

type session struct {
	Expires time.Time
	CSRF    string
	User    User
}
type attempts struct {
	Since time.Time
	Count int
}
type authentication struct {
	mu       sync.Mutex
	key      [32]byte
	sessions map[[32]byte]session
	attempts map[string]attempts
	secure   bool
	store    Store
	workers  chan struct{}
}

func newAuth(key string, secure bool, store Store) *authentication {
	return &authentication{key: sha256.Sum256([]byte(key)), sessions: map[[32]byte]session{}, attempts: map[string]attempts{}, secure: secure, store: store, workers: make(chan struct{}, 4)}
}
func (a *authentication) login(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	now := time.Now()
	a.mu.Lock()
	for k, v := range a.attempts {
		if now.Sub(v.Since) > time.Minute {
			delete(a.attempts, k)
		}
	}
	bucket, ok := a.attempts[host]
	if !ok {
		if len(a.attempts) >= 1024 {
			a.mu.Unlock()
			http.Error(w, "try later", 429)
			return
		}
		bucket = attempts{Since: now}
	}
	if bucket.Count >= 10 {
		a.mu.Unlock()
		w.Header().Set("Retry-After", "60")
		http.Error(w, "try later", 429)
		return
	}
	bucket.Count++
	a.attempts[host] = bucket
	a.mu.Unlock()
	var v struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, 1024, &v) {
		return
	}
	select {
	case a.workers <- struct{}{}:
		defer func() { <-a.workers }()
	default:
		http.Error(w, "try later", 429)
		return
	}
	count, err := a.store.AdminUserCount(r.Context())
	if err != nil {
		http.Error(w, "authentication unavailable", 503)
		return
	}
	user := User{Role: "administrator"}
	valid := false
	if count == 0 && v.Token != "" {
		provided := sha256.Sum256([]byte(v.Token))
		valid = subtle.ConstantTimeCompare(provided[:], a.key[:]) == 1
	} else {
		u, e := a.store.AdminUser(r.Context(), v.Username)
		// Equal work for absent users, disabled users and incorrect passwords.
		hash := "pbkdf2-sha256-600000$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000"
		if e == nil {
			hash = u.PasswordHash
		}
		valid = CheckPassword(hash, v.Password) && e == nil && !u.Disabled
		user = u
	}
	if !valid {
		http.Error(w, "unauthorized", 401)
		return
	}
	user.PasswordHash = ""
	if err = a.store.AdminLogin(r.Context(), user); err != nil {
		http.Error(w, "authentication unavailable", 503)
		return
	}
	cookie, err := randomToken()
	if err != nil {
		http.Error(w, "session unavailable", 503)
		return
	}
	csrf, err := randomToken()
	if err != nil {
		http.Error(w, "session unavailable", 503)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, v := range a.sessions {
		if now.After(v.Expires) || v.User.Username == "" && user.Username != "" {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) >= 128 {
		http.Error(w, "session limit reached", 503)
		return
	}
	a.sessions[sha256.Sum256([]byte(cookie))] = session{Expires: now.Add(8 * time.Hour), CSRF: csrf, User: user}
	http.SetCookie(w, &http.Cookie{Name: "cerber_admin", Value: cookie, Path: "/admin", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 60 * 60})
	writeJSON(w, map[string]bool{"ok": true})
}
func (a *authentication) current(r *http.Request) (session, bool) {
	cookie, err := r.Cookie("cerber_admin")
	if err != nil || !ValidKey(cookie.Value) {
		return session{}, false
	}
	hash := sha256.Sum256([]byte(cookie.Value))
	a.mu.Lock()
	defer a.mu.Unlock()
	v, ok := a.sessions[hash]
	if ok && time.Now().After(v.Expires) {
		delete(a.sessions, hash)
		ok = false
	}
	if ok {
		if v.User.Username == "" {
			n, e := a.store.AdminUserCount(r.Context())
			ok = e == nil && n == 0
		} else {
			u, e := a.store.AdminUser(r.Context(), v.User.Username)
			ok = e == nil && !u.Disabled && u.Version == v.User.Version
			if ok {
				u.PasswordHash = ""
				v.User = u
			}
		}
		if !ok {
			delete(a.sessions, hash)
		}
	}
	return v, ok
}
func (a *authentication) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("cerber_admin"); err == nil {
		a.mu.Lock()
		delete(a.sessions, sha256.Sum256([]byte(c.Value)))
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "cerber_admin", Path: "/admin", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, map[string]bool{"ok": true})
}
