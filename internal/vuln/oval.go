// SPDX-License-Identifier: Apache-2.0
package vuln

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/rkislov/cerber/internal/inventory"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const ovalNS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
const linuxOvalNS = ovalNS + "#linux"

type ovalSource struct{ ID, URL, Platform, Scheme string }

var ovalSources = map[string]ovalSource{
	"alt-p10":          {"alt-p10", "https://rdb.altlinux.org/api/errata/export/oval/p10", "ALT Linux branch p10", "rpm"},
	"alt-p11":          {"alt-p11", "https://rdb.altlinux.org/api/errata/export/oval/p11", "ALT Linux branch p11", "rpm"},
	"redos-7.3":        {"redos-7.3", "https://redos.red-soft.ru/support/secure/7.3/redos.xml", "RED OS 7.3", "rpm"},
	"redos-8":          {"redos-8", "https://redos.red-soft.ru/support/secure/8.0/redos.xml", "RED OS 8.0", "rpm"},
	"astra-1.7-x86_64": {"astra-1.7-x86_64", "https://dl.astralinux.ru/astra/oval/1.7_x86-64/oval-definitions-alse-1.7.xml", "Astra Linux 1.7", "debian"},
	"astra-1.8-x86_64": {"astra-1.8-x86_64", "https://dl.astralinux.ru/astra/oval/1.8_x86-64/oval-definitions-alse-1.8.xml", "Astra Linux 1.8", "debian"},
}

func sourceForInventory(s inventory.Snapshot) (ovalSource, bool) {
	id := ""
	switch s.OS.DistributionID {
	case "altlinux":
		if branch := altBranch(s.OS); branch != "" {
			id = "alt-" + branch
		}
	case "redos":
		if s.OS.Version == "7.3" {
			id = "redos-7.3"
		}
		if s.OS.Version == "8" || s.OS.Version == "8.0" {
			id = "redos-8"
		}
	case "astra":
		if s.OS.Architecture != "x86_64" && s.OS.Architecture != "amd64" {
			break
		}
		switch s.OS.Version {
		case "1.7", "1.7_x86-64":
			id = "astra-1.7-x86_64"
		case "1.8", "1.8_x86-64":
			id = "astra-1.8-x86_64"
		}
	}
	src, ok := ovalSources[id]
	return src, ok
}

type OVALSourceStatus struct {
	ID       string    `json:"id"`
	URL      string    `json:"url"`
	At       time.Time `json:"at"`
	Attempt  time.Time `json:"attempt"`
	Modified time.Time `json:"modified"`
	SHA256   string    `json:"sha256"`
	Error    string    `json:"error,omitempty"`
	Records  int       `json:"records"`
}
type ovalCheck struct {
	Name  string `json:"name"`
	Fixed string `json:"fixed"`
}
type ovalRecord struct {
	ID          string      `json:"id"`
	Definitions []string    `json:"definitions"`
	Checks      []ovalCheck `json:"checks"`
	Unsupported bool        `json:"unsupported"`
}
type ovalDefinition struct {
	ID       string `xml:"id,attr"`
	Class    string `xml:"class,attr"`
	Metadata struct {
		Platforms []string `xml:"affected>platform"`
		Refs      []struct {
			Source string `xml:"source,attr"`
			ID     string `xml:"ref_id,attr"`
		} `xml:"reference"`
	} `xml:"metadata"`
	Criteria ovalCriteria `xml:"criteria"`
}
type ovalCriteria struct {
	Invalid  bool           `xml:"-"`
	Operator string         `xml:"operator,attr"`
	Negate   string         `xml:"negate,attr"`
	Criteria []ovalCriteria `xml:"criteria"`
	Tests    []struct {
		Ref    string `xml:"test_ref,attr"`
		Negate string `xml:"negate,attr"`
	} `xml:"criterion"`
	Extend []struct{} `xml:"extend_definition"`
}
type ovalNode struct {
	depth    int
	Name     xml.Name
	Attrs    []xml.Attr
	Text     string
	Children []ovalNode
}

func (n *ovalNode) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if n.depth > 16 {
		return fmt.Errorf("OVAL element nesting limit")
	}
	n.Name = start.Name
	n.Attrs = start.Attr
	for {
		t, e := d.Token()
		if e != nil {
			return e
		}
		switch t := t.(type) {
		case xml.StartElement:
			if len(n.Children) > 1024 {
				return fmt.Errorf("oversized OVAL element")
			}
			child := ovalNode{depth: n.depth + 1}
			if e = d.DecodeElement(&child, &t); e != nil {
				return e
			}
			n.Children = append(n.Children, child)
		case xml.CharData:
			if len(n.Text)+len(t) > 4096 {
				return fmt.Errorf("oversized OVAL text")
			}
			n.Text += string(t)
		case xml.Directive:
			return fmt.Errorf("OVAL directives not accepted")
		case xml.EndElement:
			n.Text = strings.TrimSpace(n.Text)
			return nil
		}
	}
}
func (n ovalNode) attr(name string) string {
	for _, a := range n.Attrs {
		if a.Name.Local == name && a.Name.Space == "" {
			return a.Value
		}
	}
	return ""
}
func (n ovalNode) attrsAllowed(names ...string) bool {
	for _, a := range n.Attrs {
		if a.Name.Space == "xmlns" || a.Name.Local == "xmlns" {
			continue
		}
		ok := false
		for _, s := range names {
			if a.Name.Space == "" && a.Name.Local == s {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
func criteriaTests(c ovalCriteria, depth int) ([]string, bool) {
	if c.Invalid || depth > 16 || c.Negate != "" && c.Negate != "false" || len(c.Extend) > 0 {
		return nil, false
	}
	count := len(c.Criteria) + len(c.Tests)
	if count == 0 || count > 10000 || count > 1 && c.Operator != "OR" {
		return nil, false
	}
	out := []string{}
	for _, t := range c.Tests {
		if t.Ref == "" || t.Negate != "" && t.Negate != "false" {
			return nil, false
		}
		out = append(out, t.Ref)
	}
	for _, n := range c.Criteria {
		ids, ok := criteriaTests(n, depth+1)
		if !ok {
			return nil, false
		}
		out = append(out, ids...)
	}
	return out, true
}

// parseOVAL accepts only an explicit OR of native package EVR < fixed checks.
// It never flattens AND/negation/platform tests into an unconditional fix.
func parseOVAL(r io.Reader, source ovalSource) (map[string]ovalRecord, time.Time, error) {
	d := xml.NewDecoder(r)
	root, e := d.Token()
	for e == nil {
		if _, ok := root.(xml.StartElement); ok {
			break
		}
		if _, ok := root.(xml.Directive); ok {
			return nil, time.Time{}, fmt.Errorf("OVAL directive")
		}
		root, e = d.Token()
	}
	if e != nil {
		return nil, time.Time{}, e
	}
	start, ok := root.(xml.StartElement)
	if !ok || start.Name.Local != "oval_definitions" || start.Name.Space != ovalNS {
		return nil, time.Time{}, fmt.Errorf("unexpected OVAL root")
	}
	defs := []ovalDefinition{}
	alt := strings.HasPrefix(source.ID, "alt-")
	guardTests := map[string]bool{}
	tests, objects, states := map[string][2]string{}, map[string][2]string{}, map[string][2]string{}
	var modified time.Time
	sections := map[string]bool{}
	for {
		tok, e := d.Token()
		if e != nil {
			return nil, modified, e
		}
		switch t := tok.(type) {
		case xml.Directive:
			return nil, modified, fmt.Errorf("OVAL directives rejected")
		case xml.StartElement:
			sec := t.Name.Local
			if t.Name.Space != ovalNS || sections[sec] {
				return nil, modified, fmt.Errorf("unexpected/duplicate OVAL section")
			}
			sections[sec] = true
			if sec == "generator" {
				var g struct {
					Timestamp string `xml:"timestamp"`
				}
				if e = d.DecodeElement(&g, &t); e != nil {
					return nil, modified, e
				}
				modified, _ = time.Parse(time.RFC3339, g.Timestamp)
				if modified.IsZero() {
					modified, _ = time.Parse("2006-01-02T15:04:05", g.Timestamp)
				}
				continue
			}
			if sec != "definitions" && sec != "tests" && sec != "objects" && sec != "states" {
				if e = d.Skip(); e != nil {
					return nil, modified, e
				}
				continue
			}
			for {
				inner, e := d.Token()
				if e != nil {
					return nil, modified, e
				}
				if _, ok := inner.(xml.Directive); ok {
					return nil, modified, fmt.Errorf("OVAL directive")
				}
				if end, ok := inner.(xml.EndElement); ok && end.Name == t.Name {
					break
				}
				item, ok := inner.(xml.StartElement)
				if !ok {
					continue
				}
				if sec == "definitions" {
					if len(defs) >= 100000 || item.Name.Local != "definition" || item.Name.Space != ovalNS {
						return nil, modified, fmt.Errorf("invalid OVAL definition")
					}
					var def ovalDefinition
					if e = d.DecodeElement(&def, &item); e != nil {
						return nil, modified, e
					}
					defs = append(defs, def)
				} else {
					var n ovalNode
					if e = d.DecodeElement(&n, &item); e != nil {
						return nil, modified, e
					}
					m := tests
					if sec == "objects" {
						m = objects
					}
					if sec == "states" {
						m = states
					}
					id := n.attr("id")
					if id == "" || len(m) >= 250000 {
						return nil, modified, fmt.Errorf("invalid OVAL identity/bounds")
					}
					if _, exists := m[id]; exists {
						return nil, modified, fmt.Errorf("duplicate OVAL identity")
					}
					m[id] = compactOVALNode(n, sec, source)
					if alt && n.Name.Space == independentOvalNS {
						m[id] = compactALTNode(n, sec, source)
						if sec == "tests" {
							guardTests[id] = true
						}
					}
				}
			}
		case xml.EndElement:
			if t.Name == start.Name {
				goto done
			}
		}
	}
done:
	for {
		t, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, modified, e
		}
		if c, ok := t.(xml.CharData); !ok || strings.TrimSpace(string(c)) != "" {
			return nil, modified, fmt.Errorf("trailing OVAL content")
		}
	}
	if len(defs) == 0 || modified.IsZero() || modified.After(time.Now().Add(24*time.Hour)) {
		return nil, modified, fmt.Errorf("empty OVAL or invalid generator timestamp")
	}
	checks := map[string]ovalCheck{}
	guards := map[string]bool{}
	for id, t := range tests {
		name, fixed := objects[t[0]][0], states[t[1]][0]
		if guardTests[id] {
			if name == "@alt-platform" && fixed == "@"+strings.TrimPrefix(source.ID, "alt-p") {
				guards[id] = true
			}
			continue
		}
		if validPackageName(name) && fixed != "" {
			checks[id] = ovalCheck{Name: name, Fixed: fixed}
		}
	}

	out := map[string]ovalRecord{}
	seenDefs := map[string]bool{}
	for _, def := range defs {
		if def.ID == "" || seenDefs[def.ID] {
			return nil, modified, fmt.Errorf("duplicate OVAL definition")
		}
		seenDefs[def.ID] = true
		ids := []string{}
		for _, r := range def.Metadata.Refs {
			if r.Source == "CVE" && cveID.MatchString(r.ID) {
				ids = append(ids, r.ID)
			}
		}
		if len(ids) == 0 {
			continue
		}
		platform := len(def.Metadata.Platforms) == 1 && def.Metadata.Platforms[0] == source.Platform
		refs, supported := criteriaTests(def.Criteria, 0)
		if alt {
			refs, supported = altCriteriaTests(def.Criteria, guards)
		}
		supported = supported && platform && (def.Class == "vulnerability" || alt && def.Class == "patch")
		list := []ovalCheck{}
		for _, ref := range refs {
			check, ok := checks[ref]
			if !ok {
				supported = false
			} else {
				list = append(list, check)
			}
		}
		for _, id := range ids {
			v := out[id]
			v.ID = id
			v.Definitions = append(v.Definitions, def.ID)
			v.Checks = append(v.Checks, list...)
			v.Unsupported = v.Unsupported || !supported
			out[id] = v
		}
	}
	if len(out) == 0 && !alt {
		return nil, modified, fmt.Errorf("OVAL has no CVE references")
	}
	return out, modified, nil
}
func validPackageName(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for _, c := range []byte(s) {
		if !alpha(c) && !digit(c) && c != '+' && c != '-' && c != '.' && c != '_' {
			return false
		}
	}
	return true
}
func (c *Catalog) ovalStatus(ctx context.Context, id string) OVALSourceStatus {
	var p string
	var s OVALSourceStatus
	if c.db.QueryRowContext(ctx, "SELECT payload FROM vendor_oval_sources WHERE id=?", id).Scan(&p) == nil {
		json.Unmarshal([]byte(p), &s)
	}
	return s
}
func (c *Catalog) SyncOVAL(ctx context.Context, bindings []InventoryBinding) {
	if !c.ovalBusy.CompareAndSwap(false, true) {
		return
	}
	defer c.ovalBusy.Store(false)
	force := c.ovalForce.Swap(false)
	wanted := map[string]ovalSource{}
	for _, b := range bindings {
		if b.Link.State == "linked" {
			if src, ok := sourceForInventory(b.Snapshot); ok {
				wanted[src.ID] = src
			}
		}
	}
	ids := []string{}
	for id := range wanted {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		src := wanted[id]
		status := c.ovalStatus(ctx, id)
		if !force && (status.Error == "" && !status.At.IsZero() && time.Since(status.At) < 24*time.Hour || time.Since(status.Attempt) < time.Hour) {
			continue
		}
		status.ID, status.URL, status.Attempt = id, src.URL, time.Now().UTC()
		var records map[string]ovalRecord
		var modified time.Time
		var digest string
		req, e := http.NewRequestWithContext(ctx, "GET", src.URL, nil)
		if e != nil {
			return
		}
		req.Header.Set("User-Agent", "Cerber-SIEM/1")
		req.Header.Set("Accept", "application/xml")
		resp, e := ovalClient.Do(req)
		if e == nil {
			if resp.StatusCode != 200 {
				e = fmt.Errorf("OVAL HTTP %d", resp.StatusCode)
			} else {
				hash := sha256.New()
				limited := &io.LimitedReader{R: resp.Body, N: 128<<20 + 1}
				if strings.HasPrefix(src.ID, "alt-") {
					records, modified, e = parseALTZip(io.TeeReader(limited, hash), src, filepath.Dir(c.path))
				} else {
					records, modified, e = parseOVAL(io.TeeReader(limited, hash), src)
				}
				if limited.N <= 0 {
					e = fmt.Errorf("OVAL exceeds 128 MiB")
				}
				digest = hex.EncodeToString(hash.Sum(nil))
			}
			resp.Body.Close()
		}
		if e != nil {
			status.Error = e.Error()
			p, _ := json.Marshal(status)
			c.db.ExecContext(ctx, "INSERT OR REPLACE INTO vendor_oval_sources VALUES(?,?)", id, string(p))
			continue
		}
		tx, e := c.db.BeginTx(ctx, nil)
		if e != nil {
			return
		}
		_, e = tx.ExecContext(ctx, "DELETE FROM vendor_oval_records WHERE source=?", id)
		if e == nil {
			for key, v := range records {
				p, _ := json.Marshal(v)
				if _, e = tx.ExecContext(ctx, "INSERT INTO vendor_oval_records VALUES(?,?,?)", id, key, string(p)); e != nil {
					break
				}
			}
		}
		if e == nil {
			status.At, status.Modified, status.SHA256, status.Error, status.Records = time.Now().UTC(), modified, digest, "", len(records)
			p, _ := json.Marshal(status)
			_, e = tx.ExecContext(ctx, "INSERT OR REPLACE INTO vendor_oval_sources VALUES(?,?)", id, string(p))
		}
		if e == nil {
			e = tx.Commit()
		}
		if e != nil {
			tx.Rollback()
			return
		}
	}
}

var ovalClient = &http.Client{Timeout: 90 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (c *Catalog) AssessPackage(ctx context.Context, m Match, b InventoryBinding, now time.Time) PackageAssessment {
	if strings.EqualFold(b.Snapshot.OS.Family, "windows") {
		return c.AssessWindows(ctx, m, b, now)
	}
	if b.Snapshot.OS.DistributionID == "ubuntu" {
		return c.AssessUbuntu(ctx, m, b, now)
	}
	a := unknownAssessment(b, now, "Для дистрибутива, выпуска и архитектуры нет подключённого адаптера производителя")
	a.Rule = "vendor-oval-package/1"
	a.Release = b.Snapshot.OS.Version
	if b.Link.State != "linked" {
		a.Reason = b.Link.Reason
		return a
	}
	src, ok := sourceForInventory(b.Snapshot)
	if !ok {
		return a
	}
	snap := b.Snapshot
	if snap.CollectedAt.IsZero() || now.Sub(snap.CollectedAt) > 24*time.Hour || snap.CollectedAt.After(now.Add(5*time.Minute)) || snap.CoverageStatus("packages") != "complete" {
		a.Reason = "Нет полного свежего инвентаря пакетов"
		return a
	}
	if src.Scheme == "debian" && snap.PackageManager != "apt" || src.Scheme == "rpm" && snap.PackageManager != "dnf" && snap.PackageManager != "yum" && !(strings.HasPrefix(src.ID, "alt-") && snap.PackageManager == "apt-rpm") {
		return a
	}
	ids := map[string]bool{}
	for _, id := range append([]string{m.ID}, m.CVEs...) {
		if cveID.MatchString(id) {
			ids[id] = true
		}
	}
	if len(ids) != 1 {
		a.Reason = "Требуется индивидуальная запись CVE"
		return a
	}
	for id := range ids {
		a.CVE = id
	}
	status := c.ovalStatus(ctx, src.ID)
	a.SourceURL, a.SourceSHA256, a.SourceFetched, a.SourceModified = src.URL, status.SHA256, status.At, status.Modified
	a.SourceName = src.Platform + " OVAL"
	if status.At.IsZero() || status.Error != "" || now.Sub(status.At) > 24*time.Hour || status.At.After(now.Add(5*time.Minute)) {
		a.Reason = "OVAL производителя отсутствует, устарел или не обновился"
		return a
	}
	var p string
	var record ovalRecord
	if c.db.QueryRowContext(ctx, "SELECT payload FROM vendor_oval_records WHERE source=? AND id=?", src.ID, a.CVE).Scan(&p) != nil || json.Unmarshal([]byte(p), &record) != nil || record.Unsupported || len(record.Checks) == 0 {
		a.Reason = "Нет полностью поддержанного определения OVAL для CVE и выпуска; отсутствие записи не доказывает исправление"
		return a
	}
	roles := servicePackages(m.CPE)
	if src.Scheme == "rpm" {
		roles = rpmServicePackages(m.CPE)
		if strings.HasPrefix(src.ID, "alt-") && roles["httpd"] {
			roles = map[string]bool{"apache2-httpd": true, "apache2": true}
		}
	}
	if len(roles) == 0 {
		return a
	}
	roleFound := false
	uncertain := false
	for _, check := range record.Checks {
		for _, component := range snap.Components {
			if component.Name != check.Name || component.Kind != "package" || component.State != "installed" || component.VersionScheme != src.Scheme || component.Source != map[string]string{"rpm": "rpm-query", "debian": "dpkg-query"}[src.Scheme] {
				continue
			}
			versions := component.InstalledVersions
			if len(versions) == 0 {
				versions = []string{component.Version}
			}
			for _, version := range versions {
				var cmp int
				var e error
				if strings.HasPrefix(src.ID, "alt-") && strings.ContainsAny(version+check.Fixed, "~^") {
					uncertain = true
					continue
				}
				if src.Scheme == "rpm" {
					cmp, e = CompareRPM(version, check.Fixed)
				} else {
					cmp, e = CompareDebian(version, check.Fixed)
				}
				if e != nil {
					uncertain = true
					continue
				}
				if roles[component.Name] {
					roleFound = true
				}
				state := "fixed"
				if cmp < 0 {
					state = "affected"
				}
				a.Packages = append(a.Packages, PackageEvidence{Name: component.Name, Architecture: component.Architecture, Installed: version, Fixed: check.Fixed, Status: state})
			}
		}
	}
	if uncertain || !roleFound || len(a.Packages) == 0 {
		a.Reason = "Не подтверждена роль установленного пакета либо его полная версия"
		return a
	}
	a.Status = "fixed"
	for _, p := range a.Packages {
		if p.Status == "affected" {
			a.Status = "affected"
		}
	}
	a.Definitions = record.Definitions
	a.Reason = "Сравнены установленные пакеты с закрытыми условиями OVAL производителя для точного выпуска ОС. Проверяется пакет, а не эксплуатация или версия работающего процесса."
	return a
}
func rpmServicePackages(cpe string) map[string]bool {
	roles := servicePackages(cpe)
	if roles["apache2-bin"] {
		return map[string]bool{"httpd": true}
	}
	if roles["dovecot-core"] {
		return map[string]bool{"dovecot": true}
	}
	if roles["libssl3"] {
		return map[string]bool{"openssl-libs": true}
	}
	if roles["exim4-daemon-light"] {
		return map[string]bool{"exim": true}
	}
	return roles
}

func (c *ovalCriteria) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	n := ovalNode{}
	if e := d.DecodeElement(&n, &start); e != nil {
		return e
	}
	var convert func(ovalNode) ovalCriteria
	convert = func(n ovalNode) ovalCriteria {
		out := ovalCriteria{Operator: n.attr("operator"), Negate: n.attr("negate")}
		if n.Name.Space != ovalNS || n.Name.Local != "criteria" || !n.attrsAllowed("operator", "negate", "comment", "applicability_check") || n.attr("applicability_check") == "true" {
			out.Invalid = true
		}
		for _, child := range n.Children {
			switch child.Name.Local {
			case "criteria":
				out.Criteria = append(out.Criteria, convert(child))
			case "criterion":
				if child.Name.Space != ovalNS || !child.attrsAllowed("test_ref", "negate", "comment", "applicability_check") || len(child.Children) > 0 || child.attr("applicability_check") == "true" {
					out.Invalid = true
				}
				out.Tests = append(out.Tests, struct {
					Ref    string `xml:"test_ref,attr"`
					Negate string `xml:"negate,attr"`
				}{child.attr("test_ref"), child.attr("negate")})
			default:
				out.Invalid = true
			}
		}
		return out
	}
	*c = convert(n)
	return nil
}

// Keep only validated native identities/references, not XML descriptions/comments.
func compactOVALNode(n ovalNode, section string, source ovalSource) [2]string {
	empty := [2]string{}
	kind, datatype := "rpminfo", "evr_string"
	if source.Scheme == "debian" {
		kind, datatype = "dpkginfo", "debian_evr_string"
	}
	if n.Name.Space != linuxOvalNS {
		return empty
	}
	if section == "tests" {
		if n.Name.Local != kind+"_test" || !n.attrsAllowed("id", "version", "comment", "check", "check_existence", "state_operator") || n.attr("check") != "all" || n.attr("check_existence") != "at_least_one_exists" && !(strings.HasPrefix(source.ID, "alt-") && n.attr("check_existence") == "") || len(n.Children) != 2 {
			return empty
		}
		out := empty
		for _, c := range n.Children {
			if c.Name.Space != linuxOvalNS || len(c.Children) > 0 {
				return empty
			}
			switch c.Name.Local {
			case "object":
				if !c.attrsAllowed("object_ref") {
					return empty
				}
				out[0] = c.attr("object_ref")
			case "state":
				if !c.attrsAllowed("state_ref") {
					return empty
				}
				out[1] = c.attr("state_ref")
			default:
				return empty
			}
		}
		return out
	}
	if !n.attrsAllowed("id", "version", "comment") || len(n.Children) != 1 {
		return empty
	}
	c := n.Children[0]
	if c.Name.Space != linuxOvalNS || len(c.Children) > 0 {
		return empty
	}
	if section == "objects" {
		if n.Name.Local != kind+"_object" || c.Name.Local != "name" || !c.attrsAllowed("operation", "datatype") || c.attr("operation") != "" && c.attr("operation") != "equals" || c.attr("datatype") != "" && c.attr("datatype") != "string" || !validPackageName(c.Text) {
			return empty
		}
		return [2]string{c.Text, ""}
	}
	if n.Name.Local != kind+"_state" || c.Name.Local != "evr" || !c.attrsAllowed("operation", "datatype") || c.attr("operation") != "less than" || c.attr("datatype") != datatype {
		return empty
	}
	var e error
	if source.Scheme == "rpm" {
		_, _, _, e = rpmParts(c.Text)
	} else {
		_, _, _, e = debParts(c.Text)
	}
	if e != nil {
		return empty
	}
	return [2]string{c.Text, ""}
}
