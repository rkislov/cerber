// SPDX-License-Identifier: Apache-2.0
package directory

import (
	"context"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/rkislov/cerber/internal/telemetry"
)

func sidBytes(parts ...uint32) []byte {
	b := make([]byte, 8+4*len(parts))
	b[0] = 1
	b[1] = byte(len(parts))
	b[7] = 5
	for i, n := range parts {
		binary.LittleEndian.PutUint32(b[8+i*4:], n)
	}
	return b
}
func entry(attrs map[string]string) *ldap.Entry {
	return ldap.NewEntry("CN=fixture,DC=lab,DC=example", func() map[string][]string {
		v := map[string][]string{}
		for k, s := range attrs {
			v[k] = []string{s}
		}
		return v
	}())
}

type fakeLDAP struct {
	user                 *ldap.Entry
	calls                int
	bindErr, searchErr   error
	last                 *ldap.SearchRequest
	ambiguous, referrals bool
}

func (f *fakeLDAP) Bind(dn, password string) error {
	if dn != "svc@lab.example" || password != "fixture-secret" {
		return errors.New("bad test bind")
	}
	return f.bindErr
}
func (f *fakeLDAP) Close() error { return nil }
func (f *fakeLDAP) Search(q *ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.calls++
	f.last = q
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	var v *ldap.Entry
	switch q.BaseDN {
	case "":
		v = entry(map[string]string{"configurationNamingContext": "CN=Configuration,DC=lab,DC=example", "defaultNamingContext": "DC=lab,DC=example"})
	case "CN=Partitions,CN=Configuration,DC=lab,DC=example":
		v = entry(map[string]string{"dnsRoot": "lab.example", "nETBIOSName": "LAB", "nCName": "DC=lab,DC=example"})
	default:
		if q.Scope == ldap.ScopeBaseObject {
			v = entry(map[string]string{"objectSid": string(sidBytes(21, 1, 2, 3))})
		} else {
			v = f.user
		}
	}
	out := &ldap.SearchResult{}
	if v != nil {
		out.Entries = []*ldap.Entry{v}
		if f.ambiguous && q.Scope == ldap.ScopeWholeSubtree {
			out.Entries = append(out.Entries, v)
		}
	}
	if f.referrals {
		out.Referrals = []string{"ldap://untrusted.example"}
	}
	return out, nil
}
func fixture() (*fakeLDAP, Config, Domain) {
	return &fakeLDAP{user: entry(map[string]string{"objectSid": string(sidBytes(21, 1, 2, 3, 1001)), "objectGUID": "1234567890123456", "sAMAccountName": "alice", "userPrincipalName": "login@alternate.example", "userAccountControl": "512", "accountExpires": "0"})}, Config{Enabled: true, URL: "ldaps://dc.lab.example", BaseDN: "DC=lab,DC=example", BindDN: "svc@lab.example", Password: "fixture-secret"}, Domain{DNS: "lab.example", NetBIOS: "lab", SID: "S-1-5-21-1-2-3", BaseDN: "DC=lab,DC=example"}
}
func TestVerifiedDNSNetBIOSImplicitUPNAndAlternateUPN(t *testing.T) {
	f, c, d := fixture()
	got, e := discover(f, c)
	if e != nil || got != d {
		t.Fatal(got, e)
	}
	at := time.Now()
	for _, q := range []Query{{Name: "alice", Realm: "LAB"}, {Name: "alice", Realm: "lab.example", SID: "S-1-5-21-1-2-3-1001"}, {Name: "alice@lab.example", Realm: "LAB", ImplicitUPN: true}, {Name: "login@alternate.example", Realm: "LAB"}} {
		p := lookup(f, d, q, at)
		if p.State != "verified" || p.SID != "S-1-5-21-1-2-3-1001" || p.DomainSID != d.SID || p.GUID == "" {
			t.Fatal(q, p)
		}
		if f.last.SizeLimit != 2 || f.last.TimeLimit != 3 || f.last.DerefAliases != ldap.NeverDerefAliases {
			t.Fatal("unbounded lookup", f.last)
		}
	}
}
func TestRejectCrossDomainAmbiguityDisabledSIDAndEscaping(t *testing.T) {
	for _, tc := range []struct {
		name, state string
		q           Query
		edit        func(*fakeLDAP)
	}{
		{"foreign", "foreign_domain", Query{Name: "alice", Realm: "OTHER"}, nil},
		{"forged realm", "foreign_domain", Query{Name: "alice@lab.example", Realm: "OTHER", ImplicitUPN: true}, nil},
		{"foreign implicit suffix", "foreign_domain", Query{Name: "alice@other.example", Realm: "LAB", ImplicitUPN: true}, nil},
		{"wrong SID", "sid_mismatch", Query{Name: "alice", Realm: "LAB", SID: "S-1-5-21-9-9-9-1001"}, nil},
		{"ambiguous", "ambiguous", Query{Name: "alice", Realm: "LAB"}, func(f *fakeLDAP) { f.ambiguous = true }},
		{"missing", "not_found", Query{Name: "alice", Realm: "LAB"}, func(f *fakeLDAP) { f.user = nil }},
		{"disabled", "disabled", Query{Name: "alice", Realm: "LAB"}, func(f *fakeLDAP) {
			f.user = entry(map[string]string{"objectSid": string(sidBytes(21, 1, 2, 3, 1001)), "objectGUID": "1234567890123456", "sAMAccountName": "alice", "userAccountControl": "514"})
		}},
		{"bad SID bytes", "mismatch", Query{Name: "alice", Realm: "LAB"}, func(f *fakeLDAP) {
			f.user.Attributes[0] = &ldap.EntryAttribute{Name: "objectSid", Values: []string{"bad"}, ByteValues: [][]byte{[]byte("bad")}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _, d := fixture()
			if tc.edit != nil {
				tc.edit(f)
			}
			p := lookup(f, d, tc.q, time.Now())
			if p.State != tc.state {
				t.Fatal(p)
			}
		})
	}
	f, _, d := fixture()
	_ = lookup(f, d, Query{Name: "*)(objectClass=*)", Realm: "LAB"}, time.Now())
	if strings.Contains(f.last.Filter, "(sAMAccountName=*)") || !strings.Contains(f.last.Filter, `\2a\29\28objectclass=\2a\29`) {
		t.Fatal("filter injection", f.last.Filter)
	}
}
func TestCacheExpiryConfigChangeAndSourceImmutability(t *testing.T) {
	f, c, _ := fixture()
	at := time.Now().UTC()
	r := New(func() Config { return c })
	r.now = func() time.Time { return at }
	dials := 0
	r.dial = func(context.Context, Config) (connection, error) { dials++; return f, nil }
	n := telemetry.Normalized{Code: "4769", Identity: &telemetry.Identity{Computer: "dc", SessionGUID: "guid"}, WindowsAuth: &telemetry.WindowsAuth{TargetName: "alice@lab.example", TargetRealm: "LAB", AccountRef: ""}}
	r.Prepare(context.Background(), Queries(n))
	v := r.Attest(n)
	if v.WindowsAuth.Directory.State != "verified" || n.WindowsAuth.Directory != nil || v.Identity.AccountSID != "" {
		t.Fatal("lost verification or source roles", v)
	}
	r.Prepare(context.Background(), Queries(n))
	if dials != 1 {
		t.Fatal("cache not reused")
	}
	at = at.Add(6 * time.Minute)
	if r.Attest(n).WindowsAuth.Directory.State != "pending" {
		t.Fatal("stale proof trusted")
	}
	f.bindErr = errors.New("secret should not appear")
	r.Prepare(context.Background(), Queries(n))
	if r.Attest(n).WindowsAuth.Directory.State != "unavailable" {
		t.Fatal("failure hidden")
	}
	r.Prepare(context.Background(), Queries(n))
	if dials != 2 {
		t.Fatal("negative cache not reused")
	}
	c.URL = "ldaps://other.lab.example"
	if r.Attest(n).WindowsAuth.Directory.State != "pending" {
		t.Fatal("old config trusted")
	}
	c.Enabled = false
	if r.Attest(n).WindowsAuth.Directory != nil {
		t.Fatal("disabled still trusted")
	}
}
func TestInputBoundsReferralsAndTLSValidation(t *testing.T) {
	f, c, _ := fixture()
	for _, url := range []string{"ldap://dc.example", "ldaps://user:pass@dc.example", "ldaps://dc.example/path", "ldaps://dc.example?x=y", "ldaps://dc.example:99999"} {
		v := c
		v.URL = url
		if v.Validate() == nil {
			t.Fatal(url)
		}
	}
	v := c
	v.CAPEM = "invalid"
	if v.Validate() == nil {
		t.Fatal("invalid CA")
	}
	f.referrals = true
	if _, e := discover(f, c); e == nil {
		t.Fatal("referrals followed")
	}
	v = c
	v.BaseDN = "OU=Users,DC=lab,DC=example"
	f.referrals = false
	if _, e := discover(f, v); e == nil {
		t.Fatal("OU accepted as domain root")
	}
	for _, b := range [][]byte{nil, {1, 5, 0, 0, 0, 0, 0, 5}, {2, 0, 0, 0, 0, 0, 0, 5}} {
		if SID(b) != "" {
			t.Fatal("invalid SID")
		}
	}
}

func TestPrepareBoundsUniqueLookups(t *testing.T) {
	f, c, _ := fixture()
	r := New(func() Config { return c })
	r.dial = func(context.Context, Config) (connection, error) { return f, nil }
	queries := []Query{}
	for i := 0; i < 200; i++ {
		queries = append(queries, Query{Name: fmt.Sprintf("user%d", i), Realm: "LAB"})
	}
	r.Prepare(context.Background(), queries)
	if f.calls != 35 {
		t.Fatalf("expected 3 metadata + 32 account searches, got %d", f.calls)
	}
}
func TestLDAPSValidatesTrustAndHostname(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	c := Config{URL: strings.Replace(server.URL, "https://", "ldaps://", 1), CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, e := connect(ctx, c)
	if e != nil {
		t.Fatal("trusted TLS", e)
	}
	conn.Close()
	wrong := c
	wrong.CAPEM = ""
	if conn, e = connect(ctx, wrong); e == nil {
		conn.Close()
		t.Fatal("untrusted certificate accepted")
	}
	wrong = c
	wrong.URL = strings.Replace(c.URL, "127.0.0.1", "localhost", 1)
	if conn, e = connect(ctx, wrong); e == nil {
		conn.Close()
		t.Fatal("wrong hostname accepted")
	}
}

func TestUserSearchIgnoresContinuationReferencesWithoutChasing(t *testing.T) {
	f, _, d := fixture()
	f.referrals = true
	p := lookup(f, d, Query{Name: "alice", Realm: "LAB"}, time.Now())
	if p.State != "verified" || f.calls != 1 {
		t.Fatal("local user lost or referral followed", p, f.calls)
	}
}
