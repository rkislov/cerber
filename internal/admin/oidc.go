// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCConfig struct {
	Issuer           string            `json:"issuer"`
	ClientID         string            `json:"client_id"`
	ClientSecretFile string            `json:"client_secret_file,omitempty"`
	RedirectURL      string            `json:"redirect_url"`
	CACert           string            `json:"ca_cert,omitempty"`
	Users            map[string]string `json:"users"`
	Scopes           []string          `json:"scopes,omitempty"`
	GroupsClaim      string            `json:"groups_claim"`
	RoleGroups       map[string]string `json:"role_groups"`
}
type oidcFlow struct {
	nonce, verifier string
	binding         [32]byte
	expires         time.Time
}
type OIDC struct {
	config   OIDCConfig
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	client   *http.Client
	mu       sync.Mutex
	flows    map[[32]byte]oidcFlow
}

var errOIDC = errors.New("OIDC configuration or authentication unavailable")

func safeIdentityURL(value string) bool {
	u, e := url.Parse(value)
	if e != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip, e := netip.ParseAddr(u.Hostname())
	return u.Scheme == "http" && e == nil && ip.IsLoopback()
}

type identityTransport struct{ base http.RoundTripper }

func (t identityTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	u := *r.URL
	u.RawQuery = ""
	if !safeIdentityURL(u.String()) {
		return nil, errOIDC
	}
	return t.base.RoundTrip(r)
}
func LoadOIDC(ctx context.Context, path string) (*OIDC, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, errOIDC
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(data) > 65536 {
		return nil, errOIDC
	}
	var c OIDCConfig
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var extra any
	if d.Decode(&c) != nil || d.Decode(&extra) != io.EOF {
		return nil, errOIDC
	}
	if !safeIdentityURL(c.Issuer) || !safeIdentityURL(c.RedirectURL) || c.ClientID == "" || len(c.ClientID) > 256 || len(c.Users) == 0 || len(c.RoleGroups) == 0 || c.GroupsClaim == "" || len(c.GroupsClaim) > 128 {
		return nil, errOIDC
	}
	redirect, _ := url.Parse(c.RedirectURL)
	if redirect.Path != "/admin/oidc/callback" {
		return nil, errOIDC
	}
	subjects := map[string]bool{}
	for name, sub := range c.Users {
		if !ValidUsername(name) || sub == "" || len(sub) > 256 || subjects[sub] {
			return nil, errOIDC
		}
		subjects[sub] = true
	}
	for role, group := range c.RoleGroups {
		if !ValidRole(role) || group == "" || len(group) > 1024 {
			return nil, errOIDC
		}
	}
	secret := ""
	if c.ClientSecretFile != "" {
		p, e := os.ReadFile(c.ClientSecretFile)
		if e != nil || len(p) > 4096 {
			return nil, errOIDC
		}
		secret = strings.TrimSuffix(strings.TrimSuffix(string(p), "\n"), "\r")
		if secret == "" {
			return nil, errOIDC
		}
	}
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if c.CACert != "" {
		p, e := os.ReadFile(c.CACert)
		if e != nil || !roots.AppendCertsFromPEM(p) {
			return nil, errOIDC
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	client := &http.Client{Timeout: 8 * time.Second, Transport: identityTransport{transport}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(oidc.ClientContext(ctx, client), 10*time.Second)
	defer cancel()
	provider, e := oidc.NewProvider(ctx, c.Issuer)
	if e != nil {
		client.CloseIdleConnections()
		return nil, errOIDC
	}
	endpoint := provider.Endpoint()
	if !safeIdentityURL(endpoint.AuthURL) || !safeIdentityURL(endpoint.TokenURL) {
		client.CloseIdleConnections()
		return nil, errOIDC
	}
	var metadata struct {
		JWKS string `json:"jwks_uri"`
	}
	if provider.Claims(&metadata) != nil || !safeIdentityURL(metadata.JWKS) {
		client.CloseIdleConnections()
		return nil, errOIDC
	}
	scopes := []string{oidc.ScopeOpenID, "profile"}
	if len(c.Scopes) > 10 {
		return nil, errOIDC
	}
	for _, scope := range c.Scopes {
		if scope == "" || len(scope) > 128 || strings.ContainsAny(scope, " \r\n\x00") {
			return nil, errOIDC
		}
		if scope != oidc.ScopeOpenID && scope != "profile" {
			scopes = append(scopes, scope)
		}
	}
	if secret == "" {
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: c.ClientID, SupportedSigningAlgs: []string{"RS256", "ES256", "PS256"}})
	return &OIDC{config: c, oauth: oauth2.Config{ClientID: c.ClientID, ClientSecret: secret, Endpoint: endpoint, RedirectURL: c.RedirectURL, Scopes: scopes}, verifier: verifier, client: client, flows: map[[32]byte]oidcFlow{}}, nil
}
func (o *OIDC) Close()                  { o.client.CloseIdleConnections() }
func (o *OIDC) Mapped(name string) bool { _, ok := o.config.Users[name]; return ok }
func (o *OIDC) handle(a *authentication, w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/oidc/login" && r.URL.Path != "/admin/oidc/callback" {
		return false
	}
	if r.Method != "GET" {
		http.Error(w, "method not allowed", 405)
		return true
	}
	redirect, _ := url.Parse(o.config.RedirectURL)
	scheme := "http"
	if a.secure || r.TLS != nil {
		scheme = "https"
	}
	if r.Host != redirect.Host || scheme != redirect.Scheme {
		http.Error(w, "unexpected origin", 400)
		return true
	}
	if r.URL.Path == "/admin/oidc/login" {
		o.begin(a, w, r)
	} else {
		o.callback(a, w, r)
	}
	return true
}
func (o *OIDC) begin(a *authentication, w http.ResponseWriter, r *http.Request) {
	if !a.allowAttempt(w, r) {
		return
	}
	state, e := randomToken()
	if e != nil {
		http.Error(w, "SSO unavailable", 503)
		return
	}
	nonce, e := randomToken()
	if e != nil {
		http.Error(w, "SSO unavailable", 503)
		return
	}
	binding, e := randomToken()
	if e != nil {
		http.Error(w, "SSO unavailable", 503)
		return
	}
	verifier := oauth2.GenerateVerifier()
	now := time.Now()
	o.mu.Lock()
	for k, f := range o.flows {
		if now.After(f.expires) {
			delete(o.flows, k)
		}
	}
	if len(o.flows) >= 128 {
		o.mu.Unlock()
		http.Error(w, "SSO busy", 429)
		return
	}
	o.flows[sha256.Sum256([]byte(state))] = oidcFlow{nonce: nonce, verifier: verifier, binding: sha256.Sum256([]byte(binding)), expires: now.Add(5 * time.Minute)}
	o.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "cerber_oidc", Value: binding, Path: "/admin/oidc", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode, MaxAge: 300})
	http.Redirect(w, r, o.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}
func (o *OIDC) callback(a *authentication, w http.ResponseWriter, r *http.Request) {
	deny := func() { http.Error(w, "SSO authentication denied; return to /admin/ and try again", 403) }
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	cookie, e := r.Cookie("cerber_oidc")
	if !ValidKey(state) || e != nil || !ValidKey(cookie.Value) || code == "" || len(code) > 4096 || r.URL.Query().Get("error") != "" {
		deny()
		return
	}
	key := sha256.Sum256([]byte(state))
	binding := sha256.Sum256([]byte(cookie.Value))
	o.mu.Lock()
	flow, ok := o.flows[key]
	if ok && subtle.ConstantTimeCompare(binding[:], flow.binding[:]) == 1 {
		delete(o.flows, key)
	} else {
		ok = false
	}
	o.mu.Unlock()
	if !ok || time.Now().After(flow.expires) {
		deny()
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "cerber_oidc", Path: "/admin/oidc", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	select {
	case a.workers <- struct{}{}:
		defer func() { <-a.workers }()
	default:
		http.Error(w, "SSO busy", 429)
		return
	}
	ctx, cancel := context.WithTimeout(oidc.ClientContext(r.Context(), o.client), 10*time.Second)
	defer cancel()
	token, e := o.oauth.Exchange(ctx, code, oauth2.VerifierOption(flow.verifier))
	if e != nil {
		deny()
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || len(raw) > 65536 {
		deny()
		return
	}
	identity, e := o.verifier.Verify(ctx, raw)
	if e != nil || subtle.ConstantTimeCompare([]byte(identity.Nonce), []byte(flow.nonce)) != 1 || identity.Subject == "" || identity.IssuedAt.IsZero() || identity.IssuedAt.After(time.Now().Add(time.Minute)) {
		deny()
		return
	}
	var claims map[string]json.RawMessage
	if identity.Claims(&claims) != nil {
		deny()
		return
	}
	var azp string
	if p, exists := claims["azp"]; exists {
		if json.Unmarshal(p, &azp) != nil || azp != o.config.ClientID {
			deny()
			return
		}
	} else if len(identity.Audience) > 1 {
		deny()
		return
	}
	username := ""
	for name, sub := range o.config.Users {
		if sub == identity.Subject {
			username = name
			break
		}
	}
	if username == "" {
		deny()
		return
	}
	user, e := a.store.AdminUser(ctx, username)
	if e != nil || user.Disabled {
		deny()
		return
	}
	var groups []string
	if json.Unmarshal(claims[o.config.GroupsClaim], &groups) != nil {
		deny()
		return
	}
	want := o.config.RoleGroups[user.Role]
	allowed := false
	for _, g := range groups {
		if want != "" && g == want {
			allowed = true
		}
	}
	if !allowed {
		deny()
		return
	}
	expires := time.Now().Add(5 * time.Minute)
	if identity.Expiry.Before(expires) {
		expires = identity.Expiry
	}
	if e = a.establish(w, r, user, "oidc", expires); e != nil {
		http.Error(w, "session unavailable", 503)
		return
	}
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}
