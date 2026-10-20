// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type oidcIssuerFixture struct {
	mu                     sync.Mutex
	nonce, challenge, mode string
	exchanges              int
	server                 *httptest.Server
	key                    *rsa.PrivateKey
	t                      *testing.T
}

func newOIDCIssuer(t *testing.T) *oidcIssuerFixture {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	f := &oidcIssuerFixture{key: key, t: t}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/auth", "token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "fixture-key", Algorithm: "RS256", Use: "sig"}}})
		case "/token":
			f.mu.Lock()
			defer f.mu.Unlock()
			f.exchanges++
			verifier := r.FormValue("code_verifier")
			hash := sha256.Sum256([]byte(verifier))
			if verifier == "" || base64.RawURLEncoding.EncodeToString(hash[:]) != f.challenge || r.FormValue("code") != "fixture-code" || r.FormValue("redirect_uri") != "http://127.0.0.1:9999/admin/oidc/callback" {
				http.Error(w, "invalid_grant", 400)
				return
			}
			now := time.Now()
			claims := map[string]any{"iss": f.server.URL, "sub": "stable-subject", "aud": "cerber-test", "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "nonce": f.nonce, "groups": []string{"Cerber Operators"}}
			switch f.mode {
			case "nonce":
				claims["nonce"] = "wrong"
			case "audience":
				claims["aud"] = "other-client"
			case "issuer":
				claims["iss"] = "https://other.example"
			case "expired":
				claims["exp"] = now.Add(-time.Minute).Unix()
			case "groups":
				claims["groups"] = []string{"Other"}
			case "subject":
				claims["sub"] = "unmapped"
			case "azp":
				claims["aud"] = []string{"cerber-test", "other"}
				claims["azp"] = "other"
			}
			token := f.sign(claims)
			if f.mode == "signature" {
				parts := strings.Split(token, ".")
				parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, 256))
				token = strings.Join(parts, ".")
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-access-token", "token_type": "Bearer", "expires_in": 600, "id_token": token})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}
func (f *oidcIssuerFixture) sign(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"fixture-key"}`))
	p, e := json.Marshal(claims)
	if e != nil {
		f.t.Error(e)
		return ""
	}
	body := header + "." + base64.RawURLEncoding.EncodeToString(p)
	hash := sha256.Sum256([]byte(body))
	sig, e := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, hash[:])
	if e != nil {
		f.t.Error(e)
		return ""
	}
	return body + "." + base64.RawURLEncoding.EncodeToString(sig)
}
func TestOIDCRealSignedFlowRejectsInvalidIdentityAndReplay(t *testing.T) {
	f := newOIDCIssuer(t)
	cfg := OIDCConfig{Issuer: f.server.URL, ClientID: "cerber-test", RedirectURL: "http://127.0.0.1:9999/admin/oidc/callback", Users: map[string]string{"domain-user": "stable-subject"}, GroupsClaim: "groups", RoleGroups: map[string]string{"operator": "Cerber Operators"}}
	p, _ := json.Marshal(cfg)
	path := filepath.Join(t.TempDir(), "oidc.json")
	os.WriteFile(path, p, 0600)
	o, e := LoadOIDC(context.Background(), path)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	s := &directoryUserStore{user: User{Username: "domain-user", Role: "operator", Version: 1}}
	a := newAuth("", false, s)
	a.oidc = o
	begin := func() (string, *http.Cookie) {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", cfg.RedirectURL[:strings.Index(cfg.RedirectURL, "/admin/")]+"/admin/oidc/login", nil)
		if !o.handle(a, w, r) || w.Code != 302 {
			t.Fatal(w.Code)
		}
		u, e := url.Parse(w.Header().Get("Location"))
		if e != nil {
			t.Fatal(e)
		}
		q := u.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" {
			t.Fatal(q)
		}
		f.mu.Lock()
		f.nonce = q.Get("nonce")
		f.challenge = q.Get("code_challenge")
		f.mu.Unlock()
		return q.Get("state"), w.Result().Cookies()[0]
	}
	callback := func(state string, c *http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", cfg.RedirectURL+"?state="+url.QueryEscape(state)+"&code=fixture-code", nil)
		if c != nil {
			r.AddCookie(c)
		}
		o.handle(a, w, r)
		return w
	}
	for _, mode := range []string{"nonce", "audience", "issuer", "expired", "groups", "subject", "azp", "signature", ""} {
		t.Run(mode, func(t *testing.T) {
			state, c := begin()
			f.mu.Lock()
			f.mode = mode
			f.mu.Unlock()
			w := callback(state, c)
			if mode != "" {
				if w.Code != 403 {
					t.Fatalf("%s accepted: %d", mode, w.Code)
				}
				return
			}
			if w.Code != 303 {
				t.Fatal(w.Code, w.Body.String())
			}
			var sessionCookie *http.Cookie
			for _, c := range w.Result().Cookies() {
				if c.Name == "cerber_admin" {
					sessionCookie = c
				}
			}
			if sessionCookie == nil || sessionCookie.MaxAge > 300 || !sessionCookie.HttpOnly {
				t.Fatal("missing bounded session")
			}
			r := httptest.NewRequest("GET", "http://127.0.0.1:9999/admin/api/session", nil)
			r.AddCookie(sessionCookie)
			if _, ok := a.current(r); !ok {
				t.Fatal("invalid session")
			}
			if w = callback(state, c); w.Code != 403 {
				t.Fatal("callback replay")
			}
			s.user.Disabled = true
			if _, ok := a.current(r); ok {
				t.Fatal("local block bypassed")
			}
			s.user.Disabled = false
		})
	}
	state, c := begin()
	if w := callback(state, nil); w.Code != 403 {
		t.Fatal("cookie binding")
	}
	if w := callback(strings.Repeat("a", 64), c); w.Code != 403 {
		t.Fatal("state binding")
	}
	// A local password must not authenticate an SSO-only mapping.
	hash, _ := HashPassword("local-fixture-password")
	s.user.PasswordHash = hash
	r := httptest.NewRequest("POST", "http://127.0.0.1:9999/admin/login", strings.NewReader(`{"username":"domain-user","password":"local-fixture-password"}`))
	r.RemoteAddr = "127.0.0.2:9999"
	w := httptest.NewRecorder()
	a.login(w, r)
	if w.Code != 401 {
		t.Fatal("SSO local password fallback")
	}
}
func TestOIDCURLPolicy(t *testing.T) {
	for _, value := range []string{"http://example.test/realm", "https://user:password@example.test/", "https://example.test/#fragment", "https://example.test/?query=x"} {
		if safeIdentityURL(value) {
			t.Fatal(value)
		}
	}
	for _, value := range []string{"https://idp.example.test/realms/company", "http://127.0.0.1:9999/realm"} {
		if !safeIdentityURL(value) {
			t.Fatal(value)
		}
	}
}
