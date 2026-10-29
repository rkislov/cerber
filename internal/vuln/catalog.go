// SPDX-License-Identifier: Apache-2.0
// Package vuln caches authoritative vulnerability records centrally. Banner matches
// are candidates, never proof that the installed distribution package is affected.
package vuln

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/rkislov/cerber/internal/attack"
	"github.com/rkislov/cerber/internal/health"
	_ "modernc.org/sqlite"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Record struct {
	CWEs            []string `json:"cwes,omitempty"`
	ContextRequired bool     `json:"context_required,omitempty"`
	Applicability   string   `json:"applicability,omitempty"`
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	Score           float64  `json:"score"`
	Vector          string   `json:"vector"`
	Severity        string   `json:"severity"`
	Source          string   `json:"source"`
	URL             string   `json:"url"`
	CVEs            []string `json:"cves"`
	CPEs            []string `json:"cpes"`
}
type Match struct {
	Verification *PackageAssessment `json:"verification,omitempty"`
	Attack       *attack.Assessment `json:"attack,omitempty"`
	Record
	Status   string    `json:"status"`
	Evidence string    `json:"evidence"`
	CPE      string    `json:"cpe"`
	BDU      []Record  `json:"bdu"`
	Fetched  time.Time `json:"fetched"`
	Stale    bool      `json:"stale"`
}
type Cache struct {
	Format  int       `json:"format"`
	At      time.Time `json:"at"`
	Attempt time.Time `json:"attempt"`
	Error   string    `json:"error"`
	Records []Record  `json:"records"`
}
type Status struct {
	Microsoft     MicrosoftStatus    `json:"microsoft"`
	OVALSources   []OVALSourceStatus `json:"oval_sources"`
	UbuntuRecords int                `json:"ubuntu_records"`
	UbuntuErrors  int                `json:"ubuntu_errors"`
	BDU           Cache              `json:"bdu"`
	BDUCount      int                `json:"bdu_count"`
	Products      int                `json:"products"`
	Errors        int                `json:"errors"`
	Pending       bool               `json:"pending"`
	Busy          bool               `json:"busy"`
	ProductErrors []string           `json:"product_errors"`
}
type Catalog struct {
	microsoftForce atomic.Bool
	microsoftBusy  atomic.Bool
	db             *sql.DB
	mu             sync.Mutex
	busy           atomic.Bool
	force          atomic.Bool
	ubuntuForce    atomic.Bool
	ubuntuBusy     atomic.Bool
	ovalBusy       atomic.Bool
	ovalForce      atomic.Bool
	path           string
}

func Open(path string) (*Catalog, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	f.Close()
	db, e := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_size_limit(67108864)")
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(4)
	_, e = db.Exec(`CREATE TABLE IF NOT EXISTS msrc_documents(id TEXT PRIMARY KEY,payload TEXT NOT NULL);CREATE TABLE IF NOT EXISTS msrc_entries(document TEXT NOT NULL,ordinal INTEGER NOT NULL,cve TEXT NOT NULL,target TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(document,ordinal));CREATE INDEX IF NOT EXISTS msrc_target ON msrc_entries(target,cve);PRAGMA journal_mode=WAL;PRAGMA busy_timeout=5000;CREATE TABLE IF NOT EXISTS vendor_oval_sources(id TEXT PRIMARY KEY,payload TEXT NOT NULL);CREATE TABLE IF NOT EXISTS vendor_oval_records(source TEXT NOT NULL,id TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(source,id));CREATE TABLE IF NOT EXISTS ubuntu_osv(cve TEXT PRIMARY KEY,payload TEXT NOT NULL);CREATE TABLE IF NOT EXISTS products(cpe TEXT PRIMARY KEY,payload TEXT NOT NULL);CREATE TABLE IF NOT EXISTS bdu(id TEXT PRIMARY KEY,payload TEXT NOT NULL);CREATE TABLE IF NOT EXISTS bdu_cve(cve TEXT NOT NULL,id TEXT NOT NULL,PRIMARY KEY(cve,id));CREATE TABLE IF NOT EXISTS bdu_cpe(cpe TEXT NOT NULL,id TEXT NOT NULL,PRIMARY KEY(cpe,id));CREATE TABLE IF NOT EXISTS bdu_software(product TEXT NOT NULL,version TEXT NOT NULL,id TEXT NOT NULL);CREATE INDEX IF NOT EXISTS bdu_software_product ON bdu_software(product);CREATE TABLE IF NOT EXISTS metadata(id TEXT PRIMARY KEY,payload TEXT NOT NULL);`)
	if e != nil {
		db.Close()
		return nil, e
	}
	return &Catalog{db: db, path: path}, nil
}
func (c *Catalog) Close() error { return c.db.Close() }

var cweID = regexp.MustCompile(`^CWE-[0-9]{1,6}$`)
var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,10}$`)
var bduID = regexp.MustCompile(`^BDU:[0-9]{4}-[0-9]{4,10}$`)

func Severity(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	}
	return "unknown"
}

// CPE accepts concrete application identities only. OS fingerprints must not be
// treated as authenticated operating-system inventory.
func CPE(raw string) string {
	if strings.HasPrefix(raw, "cpe:/a:") {
		v := strings.Split(strings.TrimPrefix(raw, "cpe:/"), ":")
		if len(v) < 4 || len(v) > 7 {
			return ""
		}
		for len(v) < 11 {
			v = append(v, "*")
		}
		raw = "cpe:2.3:" + strings.Join(v, ":")
	}
	v := strings.Split(raw, ":")
	if len(v) != 13 || v[0] != "cpe" || v[1] != "2.3" || v[2] != "a" {
		return ""
	}
	valid := regexp.MustCompile(`^[a-zA-Z0-9._+~-]+$`)
	for _, s := range v[3:6] {
		if !valid.MatchString(s) || s == "-" {
			return ""
		}
	}
	for _, s := range v[6:] {
		if s != "*" && s != "-" && !valid.MatchString(s) {
			return ""
		}
	}
	return strings.ToLower(raw)
}
func (c *Catalog) cache(ctx context.Context, key string) Cache {
	var text string
	var v Cache
	if c.db.QueryRowContext(ctx, "SELECT payload FROM products WHERE cpe=?", key).Scan(&text) == nil {
		_ = json.Unmarshal([]byte(text), &v)
	}
	return v
}
func (c *Catalog) Status(ctx context.Context) Status {
	var s Status
	s.Microsoft = c.MicrosoftStatus(ctx)
	var b string
	if c.db.QueryRowContext(ctx, "SELECT payload FROM metadata WHERE id='bdu'").Scan(&b) == nil {
		json.Unmarshal([]byte(b), &s.BDU)
	}
	c.db.QueryRowContext(ctx, "SELECT count(*) FROM bdu").Scan(&s.BDUCount)
	c.db.QueryRowContext(ctx, "SELECT count(*) FROM products").Scan(&s.Products)
	c.db.QueryRowContext(ctx, "SELECT count(*) FROM products WHERE json_extract(payload,'$.error')<>''").Scan(&s.Errors)
	rows, e := c.db.QueryContext(ctx, "SELECT cpe,json_extract(payload,'$.error') FROM products WHERE json_extract(payload,'$.error')<>'' LIMIT 10")
	if e == nil {
		for rows.Next() {
			var key, msg string
			rows.Scan(&key, &msg)
			s.ProductErrors = append(s.ProductErrors, key+": "+msg)
		}
		rows.Close()
	}
	c.db.QueryRowContext(ctx, "SELECT count(*) FROM ubuntu_osv WHERE json_extract(payload,'$.at')>'2000'").Scan(&s.UbuntuRecords)
	c.db.QueryRowContext(ctx, "SELECT count(*) FROM ubuntu_osv WHERE json_extract(payload,'$.error')<>''").Scan(&s.UbuntuErrors)
	s.Pending = c.force.Load() || c.ubuntuForce.Load() || c.ovalForce.Load()
	s.Busy = c.busy.Load() || c.ubuntuBusy.Load() || c.ovalBusy.Load()
	for id := range ovalSources {
		v := c.ovalStatus(ctx, id)
		if v.ID != "" {
			s.OVALSources = append(s.OVALSources, v)
		}
	}
	sort.Slice(s.OVALSources, func(i, j int) bool { return s.OVALSources[i].ID < s.OVALSources[j].ID })
	return s
}
func (c *Catalog) Request() {
	c.microsoftForce.Store(true)
	c.force.Store(true)
	c.ubuntuForce.Store(true)
	c.ovalForce.Store(true)
}
func (c *Catalog) Lookup(ctx context.Context, raw string) []Match {
	key := CPE(raw)
	if key == "" {
		return nil
	}
	v := c.cache(ctx, key)
	out := []Match{}
	seen := map[string]bool{}
	for _, r := range v.Records {
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		m := Match{Record: r, Status: "version_candidate", Evidence: "NVD: CPE и версия из сетевого баннера; условия окружения и исправления дистрибутива требуют проверки", CPE: key, Fetched: v.At, Stale: time.Since(v.At) > 24*time.Hour}
		if r.ContextRequired {
			m.Status = "context_required"
			m.Evidence += "; дополнительные условия применимости не проверены"
		}
		m.BDU = c.BDU(ctx, r.ID)
		out = append(out, m)
	}
	// Exact concrete BDU CPEs are usable independently of NVD availability.
	rows, e := c.db.QueryContext(ctx, "SELECT b.payload FROM bdu_cpe x JOIN bdu b ON x.id=b.id WHERE x.cpe=? LIMIT 100", key)
	if e == nil {
		for rows.Next() {
			var text string
			rows.Scan(&text)
			var r Record
			if json.Unmarshal([]byte(text), &r) == nil && !seen[r.ID] {
				out = append(out, Match{Record: r, Status: "version_candidate", Evidence: "БДУ: точное совпадение CPE; пакет и backport требуют проверки", CPE: key})
			}
		}
		rows.Close()
	}
	p, version := product(key)
	if p != "" {
		rows, e := c.db.QueryContext(ctx, "SELECT b.payload,s.version FROM bdu_software s JOIN bdu b ON s.id=b.id WHERE s.product=?", p)
		if e == nil {
			for rows.Next() {
				var text, rule string
				rows.Scan(&text, &rule)
				var r Record
				if affected(version, rule) && json.Unmarshal([]byte(text), &r) == nil && !seen[r.ID] {
					seen[r.ID] = true
					linked := false
					for _, id := range r.CVEs {
						if seen[id] {
							linked = true
						}
					}
					if !linked {
						out = append(out, Match{Record: r, Status: "version_candidate", Evidence: "БДУ: " + p + " " + version + "; диапазон: " + rule + ". Требуется проверка пакета/backport", CPE: key})
					}
				}
			}
			rows.Close()
		}
	}
	return out
}
func (c *Catalog) BDU(ctx context.Context, id string) []Record {
	out := []Record{}
	rows, e := c.db.QueryContext(ctx, "SELECT b.payload FROM bdu_cve x JOIN bdu b ON b.id=x.id WHERE x.cve=? LIMIT 30", id)
	if e != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var text string
		rows.Scan(&text)
		var r Record
		if json.Unmarshal([]byte(text), &r) == nil {
			out = append(out, r)
		}
	}
	return out
}
func (c *Catalog) Sync(ctx context.Context, cpes []string) {
	if !c.mu.TryLock() {
		return
	}
	defer c.mu.Unlock()
	c.busy.Store(true)
	defer c.busy.Store(false)
	force := c.force.Swap(false)
	status := c.Status(ctx)
	if force || time.Since(status.BDU.At) > 24*time.Hour && time.Since(status.BDU.Attempt) > 30*time.Minute {
		v := status.BDU
		v.Attempt = time.Now().UTC()
		if e := c.syncBDU(ctx); e != nil {
			v.Error = "BDU download/import failed: " + e.Error()
		} else {
			v.At = time.Now().UTC()
			v.Error = ""
		}
		b, _ := json.Marshal(v)
		c.db.ExecContext(ctx, "INSERT INTO metadata VALUES('bdu',?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", string(b))
	}
	seen := map[string]bool{}
	n := 0
	for _, raw := range cpes {
		key := CPE(raw)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		old := c.cache(ctx, key)
		if !force && (old.Format == 2 && time.Since(old.At) < 24*time.Hour || time.Since(old.Attempt) < 15*time.Minute) {
			continue
		}
		if n >= 100 {
			return
		}
		n++
		records, e := fetchNVD(ctx, key)
		old.Attempt = time.Now().UTC()
		if e != nil {
			old.Error = e.Error()
		} else {
			old.At = time.Now().UTC()
			old.Error = ""
			old.Records = records
			old.Format = 2
		}
		b, _ := json.Marshal(old)
		if _, err := c.db.ExecContext(ctx, "INSERT INTO products VALUES(?,?) ON CONFLICT(cpe) DO UPDATE SET payload=excluded.payload", key, string(b)); err != nil {
			return
		}
		timer := time.NewTimer(6 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func recordURL(id string) string {
	if cveID.MatchString(id) {
		return "https://nvd.nist.gov/vuln/detail/" + url.PathEscape(id)
	}
	if bduID.MatchString(id) {
		return "https://bdu.fstec.ru/vul/" + strings.TrimPrefix(id, "BDU:")
	}
	return ""
}

func (c *Catalog) Health(ctx context.Context) health.Database {
	return health.CheckDB(ctx, c.db, "Каталог БДУ / CVE", c.path)
}
