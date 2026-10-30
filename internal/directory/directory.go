// SPDX-License-Identifier: Apache-2.0
// Package directory verifies event principals independently of SIEM login roles.
package directory

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/rkislov/cerber/internal/telemetry"
)

type Config struct {
	Enabled  bool   `json:"enabled"`
	URL      string `json:"url"`
	BaseDN   string `json:"base_dn"`
	BindDN   string `json:"bind_dn"`
	Password string `json:"password,omitempty"`
	CAPEM    string `json:"ca_pem"`
}

var ErrConfig = errors.New("invalid directory configuration")

func (c Config) Validate() error {
	if len(c.URL) > 512 || len(c.BaseDN) > 1024 || len(c.BindDN) > 1024 || len(c.Password) > 4096 || len(c.CAPEM) > 8192 || strings.ContainsAny(c.URL+c.BaseDN+c.BindDN+c.Password, "\x00\r\n") {
		return ErrConfig
	}
	if c.URL != "" {
		u, e := url.Parse(c.URL)
		if e != nil || u.Scheme != "ldaps" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return ErrConfig
		}
		if p := u.Port(); p != "" {
			n, e := strconv.Atoi(p)
			if e != nil || n < 1 || n > 65535 {
				return ErrConfig
			}
		}
	}
	if c.BaseDN != "" {
		if _, e := ldap.ParseDN(c.BaseDN); e != nil {
			return ErrConfig
		}
	}
	if c.CAPEM != "" {
		p := x509.NewCertPool()
		if !p.AppendCertsFromPEM([]byte(c.CAPEM)) {
			return ErrConfig
		}
	}
	if c.Enabled && (c.URL == "" || c.BaseDN == "" || c.BindDN == "" || c.Password == "") {
		return ErrConfig
	}
	return nil
}

type Domain struct {
	DNS     string `json:"dns"`
	NetBIOS string `json:"netbios"`
	SID     string `json:"sid"`
	BaseDN  string `json:"base_dn"`
}
type Query struct {
	Name        string `json:"name"`
	Realm       string `json:"realm"`
	SID         string `json:"sid"`
	ImplicitUPN bool   `json:"implicit_upn"`
}

func (q Query) Key() string { b, _ := json.Marshal(q); return string(b) }
func query(ref, sid string) Query {
	p := strings.SplitN(ref, `\`, 2)
	if len(p) != 2 {
		return Query{}
	}
	return Query{Name: p[1], Realm: p[0], SID: sid}
}
func Queries(n telemetry.Normalized) []Query {
	out := []Query{}
	if n.Identity != nil && n.Identity.AccountRef != "" {
		out = append(out, query(n.Identity.AccountRef, n.Identity.AccountSID))
	}
	if n.WindowsAuth != nil {
		w := n.WindowsAuth
		q := query(w.AccountRef, "")
		if w.TargetName != "" {
			q = Query{Name: w.TargetName, Realm: w.TargetRealm, ImplicitUPN: n.Code == "4769"}
		}
		out = append(out, q)
	}
	return out
}

type cached struct {
	Proof telemetry.DirectoryProof
	Until time.Time
}
type Resolver struct {
	prepareMu  sync.Mutex
	mu         sync.Mutex
	provider   func() Config
	generation [32]byte
	cache      map[string]cached
	now        func() time.Time
	dial       func(context.Context, Config) (connection, error)
}
type connection interface {
	Bind(string, string) error
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

func New(provider func() Config) *Resolver {
	return &Resolver{provider: provider, cache: map[string]cached{}, now: time.Now, dial: connect}
}
func connect(ctx context.Context, c Config) (connection, error) {
	u, e := url.Parse(c.URL)
	if e != nil {
		return nil, ErrConfig
	}
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if c.CAPEM != "" && !roots.AppendCertsFromPEM([]byte(c.CAPEM)) {
		return nil, ErrConfig
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "636")
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname(), RootCAs: roots}}
	raw, e := d.DialContext(ctx, "tcp", host)
	if e != nil {
		return nil, e
	}
	deadline := time.Now().Add(6 * time.Second)
	if v, ok := ctx.Deadline(); ok && v.Before(deadline) {
		deadline = v
	}
	_ = raw.SetDeadline(deadline)
	l := ldap.NewConn(raw, true)
	l.Start()
	l.SetTimeout(3 * time.Second)
	return l, nil
}
func search(c connection, base string, scope, limit int, filter string, attrs ...string) ([]*ldap.Entry, error) {
	r, e := c.Search(ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, limit, 3, false, filter, attrs, nil))
	if e != nil {
		return nil, e
	}
	// AD returns continuation references for subordinate DNS naming contexts in
	// domain-root subtree searches. Keep only this server's entries: go-ldap
	// does not chase these URLs. Metadata searches must remain unambiguous.
	if len(r.Referrals) > 0 && scope != ldap.ScopeWholeSubtree {
		return nil, errors.New("directory referrals are not followed")
	}
	return r.Entries, nil
}
func one(c connection, base string, scope int, filter string, attrs ...string) (*ldap.Entry, error) {
	r, e := search(c, base, scope, 2, filter, attrs...)
	if e != nil || len(r) != 1 {
		return nil, errors.New("directory entry is absent or ambiguous")
	}
	return r[0], nil
}
func discover(c connection, cfg Config) (Domain, error) {
	root, e := one(c, "", ldap.ScopeBaseObject, "(objectClass=*)", "configurationNamingContext", "defaultNamingContext")
	if e != nil {
		return Domain{}, e
	}
	base, e := ldap.ParseDN(cfg.BaseDN)
	if e != nil {
		return Domain{}, e
	}
	def, e := ldap.ParseDN(root.GetAttributeValue("defaultNamingContext"))
	if e != nil || !base.EqualFold(def) {
		return Domain{}, errors.New("Base DN must be the controller domain root")
	}
	conf := root.GetAttributeValue("configurationNamingContext")
	if conf == "" {
		return Domain{}, ErrConfig
	}
	cross, e := one(c, "CN=Partitions,"+conf, ldap.ScopeSingleLevel, "(&(objectClass=crossRef)(nCName="+ldap.EscapeFilter(cfg.BaseDN)+"))", "dnsRoot", "nETBIOSName", "nCName")
	if e != nil {
		return Domain{}, e
	}
	entry, e := one(c, cfg.BaseDN, ldap.ScopeBaseObject, "(objectClass=domainDNS)", "objectSid")
	if e != nil {
		return Domain{}, e
	}
	sid := SID(entry.GetRawAttributeValue("objectSid"))
	if len(strings.Split(sid, "-")) != 7 || !strings.HasPrefix(sid, "S-1-5-21-") {
		return Domain{}, ErrConfig
	}
	d := Domain{strings.ToLower(cross.GetAttributeValue("dnsRoot")), strings.ToLower(cross.GetAttributeValue("nETBIOSName")), sid, cfg.BaseDN}
	if d.DNS == "" || d.NetBIOS == "" {
		return Domain{}, ErrConfig
	}
	return d, nil
}

// SID decodes AD's binary SID; invalid lengths/revisions never attest identity.
func SID(b []byte) string {
	if len(b) < 8 || b[0] != 1 || b[1] > 15 || len(b) != 8+int(b[1])*4 {
		return ""
	}
	auth := uint64(0)
	for _, v := range b[2:8] {
		auth = auth<<8 | uint64(v)
	}
	s := fmt.Sprintf("S-1-%d", auth)
	for i := 0; i < int(b[1]); i++ {
		s += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(b[8+i*4:]))
	}
	return s
}
func lookup(c connection, d Domain, q Query, at time.Time) telemetry.DirectoryProof {
	p := telemetry.DirectoryProof{State: "unresolved", CheckedAt: at, ValidUntil: at.Add(5 * time.Minute), DNS: d.DNS, NetBIOS: d.NetBIOS, DomainSID: d.SID}
	name, realm := strings.ToLower(strings.TrimSpace(q.Name)), strings.ToLower(strings.TrimSpace(q.Realm))
	if name == "" || len(name) > 320 || strings.ContainsAny(name+realm, "\x00\r\n\\") || strings.HasSuffix(strings.Split(name, "@")[0], "$") {
		p.State = "unsupported"
		return p
	}
	alias := func(s string) bool { return s == d.DNS || s == d.NetBIOS }
	filter := ""
	sam := ""
	upn := ""
	if strings.Count(name, "@") == 1 {
		parts := strings.Split(name, "@")
		if parts[0] == "" || parts[1] == "" {
			return p
		}
		if realm != "" && realm != "-" && !alias(realm) && realm != parts[1] {
			p.State = "foreign_domain"
			return p
		}
		if q.ImplicitUPN {
			if !alias(parts[1]) || realm != "" && realm != "-" && !alias(realm) {
				p.State = "foreign_domain"
				return p
			}
			sam = parts[0]
			filter = "(sAMAccountName=" + ldap.EscapeFilter(sam) + ")"
		} else {
			upn = name
			filter = "(userPrincipalName=" + ldap.EscapeFilter(name) + ")"
		}
	} else {
		if strings.Contains(name, "@") || !alias(realm) {
			p.State = "foreign_domain"
			return p
		}
		sam = name
		filter = "(sAMAccountName=" + ldap.EscapeFilter(name) + ")"
	}
	entries, e := search(c, d.BaseDN, ldap.ScopeWholeSubtree, 2, "(&(objectCategory=person)(objectClass=user)"+filter+")", "objectSid", "objectGUID", "sAMAccountName", "userPrincipalName", "userAccountControl", "msDS-User-Account-Control-Computed", "accountExpires")
	if e != nil {
		p.State = "unavailable"
		p.ValidUntil = at.Add(time.Minute)
		return p
	}
	if len(entries) == 0 {
		p.State = "not_found"
		return p
	}
	if len(entries) != 1 {
		p.State = "ambiguous"
		return p
	}
	v := entries[0]
	sid := SID(v.GetRawAttributeValue("objectSid"))
	guid := v.GetRawAttributeValue("objectGUID")
	actualSam := strings.ToLower(v.GetAttributeValue("sAMAccountName"))
	actualUPN := strings.ToLower(v.GetAttributeValue("userPrincipalName"))
	if sid == "" || !strings.HasPrefix(sid, d.SID+"-") || len(strings.Split(sid, "-")) != 8 || len(guid) != 16 || strings.Trim(hex.EncodeToString(guid), "0") == "" || actualSam == "" || sam != "" && sam != actualSam || upn != "" && upn != actualUPN {
		p.State = "mismatch"
		return p
	}
	if q.SID != "" && q.SID != sid {
		p.State = "sid_mismatch"
		return p
	}
	p.SID = sid
	p.GUID = fmt.Sprintf("%08x-%04x-%04x-%s-%s", binary.LittleEndian.Uint32(guid[:4]), binary.LittleEndian.Uint16(guid[4:6]), binary.LittleEndian.Uint16(guid[6:8]), hex.EncodeToString(guid[8:10]), hex.EncodeToString(guid[10:]))
	p.SAM = actualSam
	p.UPN = actualUPN
	flags, e := strconv.ParseUint(v.GetAttributeValue("userAccountControl"), 10, 32)
	if e != nil {
		p.State = "unresolved"
		return p
	}
	if flags&2 != 0 {
		p.State = "disabled"
		return p
	}
	if v := v.GetAttributeValue("msDS-User-Account-Control-Computed"); v != "" {
		f, e := strconv.ParseUint(v, 10, 32)
		if e != nil {
			p.State = "unresolved"
			return p
		}
		if f&0x10 != 0 {
			p.State = "locked"
			return p
		}
	}
	if expires := v.GetAttributeValue("accountExpires"); expires != "" && expires != "0" && expires != "9223372036854775807" {
		ticks, e := strconv.ParseInt(expires, 10, 64)
		if e != nil || ticks <= 0 {
			p.State = "unresolved"
			return p
		}
		if !at.Before(time.Unix(ticks/10000000-11644473600, 0)) {
			p.State = "expired"
			return p
		}
	}
	p.State = "verified"
	return p
}
func Probe(ctx context.Context, cfg Config) (Domain, error) {
	if cfg.Validate() != nil || cfg.URL == "" || cfg.BindDN == "" || cfg.Password == "" {
		return Domain{}, ErrConfig
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	c, e := connect(ctx, cfg)
	if e != nil {
		return Domain{}, errors.New("LDAPS: TLS connection failed")
	}
	defer c.Close()
	if e = c.Bind(cfg.BindDN, cfg.Password); e != nil {
		return Domain{}, errors.New("LDAPS: service bind failed")
	}
	d, e := discover(c, cfg)
	if e != nil {
		return Domain{}, errors.New("LDAPS: domain root, crossRef or domain SID could not be verified")
	}
	return d, nil
}

// Prepare performs bounded I/O before the correlator opens its SQLite transaction.
// Failed lookups are negatively cached; neither secrets nor LDAP errors enter evidence.
func (r *Resolver) Prepare(ctx context.Context, queries []Query) {
	r.prepareMu.Lock()
	defer r.prepareMu.Unlock()
	cfg := r.provider()
	b, _ := json.Marshal(cfg)
	gen := sha256.Sum256(b)
	r.mu.Lock()
	if gen != r.generation {
		r.cache = map[string]cached{}
		r.generation = gen
	}
	now := r.now().UTC()
	pending := []Query{}
	seen := map[string]bool{}
	if cfg.Enabled {
		for _, q := range queries {
			key := q.Key()
			if q.Name == "" || seen[key] {
				continue
			}
			seen[key] = true
			if v, ok := r.cache[key]; ok && now.Before(v.Until) {
				continue
			}
			if len(pending) < 32 {
				pending = append(pending, q)
			}
		}
	}
	r.mu.Unlock()
	if len(pending) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	c, e := r.dial(ctx, cfg)
	d := Domain{}
	if e == nil {
		defer c.Close()
		e = c.Bind(cfg.BindDN, cfg.Password)
	}
	if e == nil {
		d, e = discover(c, cfg)
	}
	results := map[string]cached{}
	for _, q := range pending {
		p := telemetry.DirectoryProof{State: "unavailable", CheckedAt: now, ValidUntil: now.Add(time.Minute)}
		if e == nil && ctx.Err() == nil {
			p = lookup(c, d, q, now)
		}
		results[q.Key()] = cached{p, p.ValidUntil}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.generation != gen {
		return
	}
	if len(r.cache) > 4096 {
		r.cache = map[string]cached{}
	}
	for k, v := range results {
		r.cache[k] = v
	}
}

func (r *Resolver) proof(q Query) *telemetry.DirectoryProof {
	cfg := r.provider()
	if !cfg.Enabled {
		return nil
	}
	b, _ := json.Marshal(cfg)
	if sha256.Sum256(b) != r.generation {
		return &telemetry.DirectoryProof{State: "pending"}
	}
	v, ok := r.cache[q.Key()]
	if !ok || !r.now().Before(v.Until) {
		return &telemetry.DirectoryProof{State: "pending"}
	}
	p := v.Proof
	return &p
}

// Attest enriches copies only. Source identifiers and normalized rows stay immutable.
func (r *Resolver) Attest(n telemetry.Normalized) telemetry.Normalized {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n.Identity != nil {
		v := *n.Identity
		n.Identity = &v
		if v.AccountRef != "" {
			v.Directory = r.proof(query(v.AccountRef, v.AccountSID))
		}
	}
	if n.WindowsAuth != nil {
		v := *n.WindowsAuth
		n.WindowsAuth = &v
		q := query(v.AccountRef, "")
		if v.TargetName != "" {
			q = Query{Name: v.TargetName, Realm: v.TargetRealm, ImplicitUPN: n.Code == "4769"}
		}
		v.Directory = r.proof(q)
	}
	return n
}

func (r *Resolver) Enabled() bool { return r.provider().Enabled }

// Check verifies a single principal without changing the correlation cache.
func Check(ctx context.Context, cfg Config, q Query) (telemetry.DirectoryProof, error) {
	if cfg.Validate() != nil || cfg.URL == "" || cfg.BindDN == "" || cfg.Password == "" || len(q.Name) > 320 || len(q.Realm) > 253 || len(q.SID) > 184 {
		return telemetry.DirectoryProof{}, ErrConfig
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	c, e := connect(ctx, cfg)
	if e != nil {
		return telemetry.DirectoryProof{}, errors.New("LDAPS: TLS connection failed")
	}
	defer c.Close()
	if e = c.Bind(cfg.BindDN, cfg.Password); e != nil {
		return telemetry.DirectoryProof{}, errors.New("LDAPS: service bind failed")
	}
	d, e := discover(c, cfg)
	if e != nil {
		return telemetry.DirectoryProof{}, errors.New("LDAPS: domain discovery failed")
	}
	return lookup(c, d, q, time.Now().UTC()), nil
}
