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
}

func newAuth(key string, secure bool) *authentication {
	return &authentication{key: sha256.Sum256([]byte(key)), sessions: map[[32]byte]session{}, attempts: map[string]attempts{}, secure: secure}
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
		Token string `json:"token"`
	}
	if !decodeJSON(w, r, 1024, &v) {
		return
	}
	provided := sha256.Sum256([]byte(v.Token))
	if subtle.ConstantTimeCompare(provided[:], a.key[:]) != 1 {
		http.Error(w, "unauthorized", 401)
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
		if now.After(v.Expires) {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) >= 128 {
		http.Error(w, "session limit reached", 503)
		return
	}
	a.sessions[sha256.Sum256([]byte(cookie))] = session{now.Add(8 * time.Hour), csrf}
	delete(a.attempts, host)
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
