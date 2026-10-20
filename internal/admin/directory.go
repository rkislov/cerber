// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Directory maps explicitly provisioned local identities to directory subjects.
// Local role/disable/version checks still apply to every authenticated request.
type Directory interface {
	Mapped(string) bool
	Authenticate(context.Context, string, string, string) error
	Check(context.Context, string, string) error
}
type DirectoryConfig struct {
	URL          string            `json:"url"`
	BaseDN       string            `json:"base_dn"`
	BindDN       string            `json:"bind_dn"`
	PasswordFile string            `json:"password_file"`
	CACert       string            `json:"ca_cert,omitempty"`
	Users        map[string]string `json:"users"`
	RoleGroups   map[string]string `json:"role_groups"`
}
type ldapDirectory struct {
	config   DirectoryConfig
	tls      *tls.Config
	password string
}

var errDirectory = errors.New("directory authentication unavailable or denied")

func LoadDirectory(path string) (Directory, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, errDirectory
	}
	defer f.Close()
	p, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(p) > 65536 {
		return nil, errDirectory
	}
	var c DirectoryConfig
	d := json.NewDecoder(bytes.NewReader(p))
	d.DisallowUnknownFields()
	var extra any
	if d.Decode(&c) != nil || d.Decode(&extra) != io.EOF {
		return nil, errDirectory
	}
	u, e := url.Parse(c.URL)
	if e != nil || u.Scheme != "ldaps" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || c.BindDN == "" || c.BaseDN == "" || len(c.Users) == 0 || len(c.RoleGroups) == 0 {
		return nil, errDirectory
	}
	if _, e = ldap.ParseDN(c.BaseDN); e != nil {
		return nil, errDirectory
	}
	if _, e = ldap.ParseDN(c.BindDN); e != nil {
		return nil, errDirectory
	}
	seen := map[string]bool{}
	for name, upn := range c.Users {
		key := strings.ToLower(upn)
		if !ValidUsername(name) || len(upn) > 256 || strings.Count(upn, "@") != 1 || strings.ContainsAny(upn, "\x00\r\n ") || seen[key] {
			return nil, errDirectory
		}
		seen[key] = true
	}
	for role, dn := range c.RoleGroups {
		if !ValidRole(role) {
			return nil, errDirectory
		}
		if _, e = ldap.ParseDN(dn); e != nil {
			return nil, errDirectory
		}
	}
	secret, e := os.ReadFile(c.PasswordFile)
	if e != nil || len(secret) > 1024 {
		return nil, errDirectory
	}
	password := strings.TrimSuffix(strings.TrimSuffix(string(secret), "\n"), "\r")
	if password == "" || strings.ContainsAny(password, "\x00\r\n") {
		return nil, errDirectory
	}
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if c.CACert != "" {
		pem, e := os.ReadFile(c.CACert)
		if e != nil || !roots.AppendCertsFromPEM(pem) {
			return nil, errDirectory
		}
	}
	return &ldapDirectory{config: c, password: password, tls: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname(), RootCAs: roots}}, nil
}
func (l *ldapDirectory) Mapped(name string) bool { _, ok := l.config.Users[name]; return ok }
func (l *ldapDirectory) connect(ctx context.Context) (*ldap.Conn, error) {
	u, e := url.Parse(l.config.URL)
	if e != nil {
		return nil, errDirectory
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "636")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	raw, e := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: l.tls}).DialContext(ctx, "tcp", host)
	if e != nil {
		return nil, errDirectory
	}
	deadline := time.Now().Add(8 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = raw.SetDeadline(deadline)
	conn := ldap.NewConn(raw, true)
	conn.Start()
	conn.SetTimeout(5 * time.Second)
	return conn, nil
}
func (l *ldapDirectory) lookup(c *ldap.Conn, name, role string) (string, error) {
	upn, ok := l.config.Users[name]
	group := l.config.RoleGroups[role]
	if !ok || group == "" {
		return "", errDirectory
	}
	if e := c.Bind(l.config.BindDN, l.password); e != nil {
		return "", errDirectory
	}
	filter := "(&(objectCategory=person)(objectClass=user)(userPrincipalName=" + ldap.EscapeFilter(upn) + ")(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberOf:1.2.840.113556.1.4.1941:=" + ldap.EscapeFilter(group) + "))"
	r, e := c.Search(ldap.NewSearchRequest(l.config.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false, filter, []string{"distinguishedName", "accountExpires", "msDS-User-Account-Control-Computed"}, nil))
	if e != nil || len(r.Entries) != 1 {
		return "", errDirectory
	}
	// AD rejects expired/locked users at bind; session checks additionally inspect computed lockout.
	entry := r.Entries[0]
	if !directoryAccountActive(entry, time.Now()) {
		return "", errDirectory
	}
	return entry.DN, nil
}
func (l *ldapDirectory) Authenticate(ctx context.Context, name, password, role string) error {
	if password == "" || len(password) > 256 || strings.ContainsRune(password, 0) {
		return errDirectory
	}
	c, e := l.connect(ctx)
	if e != nil {
		return e
	}
	defer c.Close()
	dn, e := l.lookup(c, name, role)
	if e != nil {
		return e
	}
	if e = c.Bind(dn, password); e != nil {
		return errDirectory
	}
	return nil
}
func (l *ldapDirectory) Check(ctx context.Context, name, role string) error {
	c, e := l.connect(ctx)
	if e != nil {
		return e
	}
	defer c.Close()
	_, e = l.lookup(c, name, role)
	return e
}
func directoryAccountActive(entry *ldap.Entry, now time.Time) bool {
	if v := entry.GetAttributeValue("msDS-User-Account-Control-Computed"); v != "" {
		flags, e := strconv.ParseUint(v, 10, 64)
		if e != nil || flags&0x10 != 0 || flags&0x800000 != 0 {
			return false
		}
	}
	if v := entry.GetAttributeValue("accountExpires"); v != "" && v != "0" && v != "9223372036854775807" {
		ticks, e := strconv.ParseInt(v, 10, 64)
		if e != nil || ticks <= 0 {
			return false
		}
		expires := time.Unix(ticks/10000000-11644473600, 0)
		if !now.Before(expires) {
			return false
		}
	}
	return true
}
