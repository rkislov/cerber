// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"context"
	"crypto/sha256"
	"errors"
	"github.com/go-ldap/ldap/v3"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type directoryFixture struct {
	denied bool
	auth   int
	checks int
}

func (d *directoryFixture) Mapped(n string) bool { return n == "domain-user" }
func (d *directoryFixture) Authenticate(_ context.Context, n, p, r string) error {
	d.auth++
	if d.denied || p != "domain-fixture-password" || r != "operator" {
		return errors.New("denied")
	}
	return nil
}
func (d *directoryFixture) Check(context.Context, string, string) error {
	d.checks++
	if d.denied {
		return errors.New("denied")
	}
	return nil
}

type directoryUserStore struct {
	Store
	user   User
	logins int
}

func (s *directoryUserStore) AdminUserCount(context.Context) (int, error) { return 1, nil }
func (s *directoryUserStore) AdminUser(_ context.Context, name string) (User, error) {
	if name != s.user.Username {
		return User{}, ErrForbidden
	}
	return s.user, nil
}
func (s *directoryUserStore) AdminLogin(_ context.Context, u User) error { s.logins++; return nil }
func TestDomainLoginNoLocalFallbackAndRevocation(t *testing.T) {
	hash, _ := HashPassword("local-fixture-password")
	s := &directoryUserStore{user: User{Username: "domain-user", Role: "operator", Version: 1, PasswordHash: hash}}
	d := &directoryFixture{}
	a := newAuth("", false, s)
	a.directory = d
	login := func(password string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://localhost/admin/login", strings.NewReader(`{"username":"domain-user","password":"`+password+`"}`))
		r.RemoteAddr = "127.0.0.1:5000"
		w := httptest.NewRecorder()
		a.login(w, r)
		return w
	}
	if w := login("local-fixture-password"); w.Code != 401 {
		t.Fatal("domain account accepted local password", w.Code)
	}
	w := login("domain-fixture-password")
	if w.Code != 200 || s.logins != 1 {
		t.Fatal(w.Code)
	}
	cookie := w.Result().Cookies()[0]
	r := httptest.NewRequest("GET", "http://localhost/admin/api/session", nil)
	r.AddCookie(cookie)
	if _, ok := a.current(r); !ok {
		t.Fatal("valid domain session")
	}
	key := sha256.Sum256([]byte(cookie.Value))
	a.mu.Lock()
	v := a.sessions[key]
	v.DirectoryChecked = time.Now().Add(-31 * time.Second)
	a.sessions[key] = v
	a.mu.Unlock()
	d.denied = true
	if _, ok := a.current(r); ok || d.checks != 1 {
		t.Fatal("domain removal not enforced")
	}
	if _, ok := a.current(r); ok {
		t.Fatal("revoked session restored")
	}
	d.denied = false
	w = login("domain-fixture-password")
	r = httptest.NewRequest("GET", "http://localhost/admin/api/session", nil)
	r.AddCookie(w.Result().Cookies()[0])
	s.user.Disabled = true
	if _, ok := a.current(r); ok {
		t.Fatal("local block bypassed")
	}
}
func TestDirectoryConfigurationRequiresTLSAndExplicitMapping(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "directory.json")
	secret := filepath.Join(dir, "bind.secret")
	os.WriteFile(secret, []byte("fixture-only"), 0600)
	config := `{"url":"ldaps://dc.example.test:636","base_dn":"DC=example,DC=test","bind_dn":"CN=reader,DC=example,DC=test","password_file":"` + filepath.ToSlash(secret) + `","users":{"domain-user":"alice@example.test"},"role_groups":{"operator":"CN=operators,DC=example,DC=test"}}`
	os.WriteFile(path, []byte(config), 0600)
	d, e := LoadDirectory(path)
	if e != nil || !d.Mapped("domain-user") || d.Mapped("root") {
		t.Fatal(d, e)
	}
	os.WriteFile(path, []byte(strings.Replace(config, "ldaps://", "ldap://", 1)), 0600)
	if _, e = LoadDirectory(path); e == nil {
		t.Fatal("plaintext directory accepted")
	}
	os.WriteFile(path, []byte(strings.Replace(config, `"role_groups":{"operator":"CN=operators,DC=example,DC=test"}`, `"role_groups":{"owner":"CN=operators,DC=example,DC=test"}`, 1)), 0600)
	if _, e = LoadDirectory(path); e == nil {
		t.Fatal("unknown role accepted")
	}
}
func TestDirectoryDisabledExpiredAndLockout(t *testing.T) {
	now := time.Now()
	for _, attrs := range []map[string][]string{{"msDS-User-Account-Control-Computed": {"16"}}, {"msDS-User-Account-Control-Computed": {"8388608"}}, {"accountExpires": {"1"}}} {
		if directoryAccountActive(ldap.NewEntry("CN=user", attrs), now) {
			t.Fatal(attrs)
		}
	}
	if !directoryAccountActive(ldap.NewEntry("CN=user", map[string][]string{"accountExpires": {"9223372036854775807"}}), now) {
		t.Fatal("nonexpiring account")
	}
}
