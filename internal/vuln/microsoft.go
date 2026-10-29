// SPDX-License-Identifier: Apache-2.0
package vuln

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rkislov/cerber/internal/health"
	"github.com/rkislov/cerber/internal/inventory"
)

const MicrosoftSource = "https://api.msrc.microsoft.com/cvrf/v3.0/"

var microsoftClient = &http.Client{Timeout: 90 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
var microsoftDocID = regexp.MustCompile(`^20[0-9]{2}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$`)
var microsoftKB = regexp.MustCompile(`^(?:KB)?([0-9]{6,8})$`)
var microsoftClientName = regexp.MustCompile(`^Windows (10|11) Version ([0-9A-Za-z]+) for (x64-based|ARM64-based|32-bit) Systems$`)
var microsoftServerName = regexp.MustCompile(`^Windows Server (2012 R2|2012|2016|2019|2022|2025)( \(Server Core installation\))?$`)

type microsoftText struct{ Value string }
type microsoftProduct struct{ ProductID, Value, CPE string }
type microsoftEntry struct {
	CVE, Title, Product, ProductID, Target, FixedBuild, KB, Severity, Vector string
	Score                                                                    float64
	Supersedes                                                               []string
	KnownNotAffected                                                         bool
}
type microsoftDocument struct {
	ID       string    `json:"id"`
	Modified time.Time `json:"modified"`
	At       time.Time `json:"at"`
	Attempt  time.Time `json:"attempt"`
	Error    string    `json:"error,omitempty"`
	SHA256   string    `json:"sha256"`
	Records  int       `json:"records"`
}
type MicrosoftStatus struct {
	Errors          int                `json:"errors"`
	Documents       int                `json:"documents"`
	Expected        int                `json:"expected"`
	Records         int                `json:"records"`
	InitialComplete bool               `json:"initial_complete"`
	Busy            bool               `json:"busy"`
	At              time.Time          `json:"at"`
	Attempt         time.Time          `json:"attempt"`
	Error           string             `json:"error,omitempty"`
	Scope           string             `json:"scope"`
	Releases        []microsoftRelease `json:"releases,omitempty"`
}
type microsoftRelease struct {
	ID                 string
	CurrentReleaseDate string
	InitialReleaseDate string
}
type WindowsEvidence struct {
	Product        string   `json:"product"`
	ProductID      string   `json:"product_id"`
	InstalledBuild string   `json:"installed_build"`
	FixedBuild     string   `json:"fixed_build,omitempty"`
	KB             string   `json:"kb,omitempty"`
	InstalledKB    string   `json:"installed_kb,omitempty"`
	Supersedence   []string `json:"supersedence,omitempty"`
}
type WindowsFinding struct {
	Record
	Assessment PackageAssessment `json:"assessment"`
	Windows    WindowsEvidence   `json:"windows"`
}
type WindowsReport struct {
	SnapshotID string           `json:"snapshot_id"`
	OS         inventory.OS     `json:"os"`
	Status     string           `json:"status"`
	Reason     string           `json:"reason"`
	Source     MicrosoftStatus  `json:"source"`
	Total      int              `json:"total"`
	Counts     map[string]int   `json:"counts"`
	Items      []WindowsFinding `json:"items"`
}

func microsoftTime(s string) time.Time {
	for _, f := range []string{time.RFC3339, "2006-01-02T15:04:05"} {
		if t, e := time.Parse(f, s); e == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
func kb(s string) string {
	m := microsoftKB.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return ""
	}
	return "KB" + m[1]
}
func productTarget(p microsoftProduct) string {
	if m := microsoftClientName.FindStringSubmatch(p.Value); m != nil {
		arch := map[string]string{"x64-based": "x64", "ARM64-based": "arm64", "32-bit": "x86"}[m[3]]
		family := "windows_" + m[1] + "_" + strings.ToLower(m[2])
		if !validMicrosoftCPE(p.CPE, family, arch) {
			return ""
		}
		return family + "|" + arch + "|client"
	}
	if m := microsoftServerName.FindStringSubmatch(p.Value); m != nil {
		family := "windows_server_" + strings.ReplaceAll(strings.ToLower(m[1]), " ", "_")
		if !validMicrosoftCPE(p.CPE, family, "x64") {
			return ""
		}
		kind := "server"
		if m[2] != "" {
			kind = "core"
		}
		return family + "|x64|" + kind
	}
	return ""
}
func windowsBuild(s string) ([4]uint64, bool) {
	var v [4]uint64
	p := strings.Split(s, ".")
	if len(p) != 4 {
		return v, false
	}
	for i, x := range p {
		if x == "" || len(x) > 10 {
			return v, false
		}
		for _, r := range x {
			if r < '0' || r > '9' {
				return v, false
			}
		}
		n, e := strconv.ParseUint(x, 10, 32)
		if e != nil {
			return v, false
		}
		v[i] = n
	}
	return v, true
}
func snapshotWindowsTarget(s inventory.Snapshot) (string, string) {
	os := s.OS
	build := os.Build
	if len(strings.Split(build, ".")) == 2 {
		v := strings.Split(os.Version, ".")
		if len(v) == 3 && strings.HasPrefix(build, v[2]+".") {
			build = v[0] + "." + v[1] + "." + build
		}
	}
	b, ok := windowsBuild(build)
	if !ok || strings.ToLower(os.Family) != "windows" {
		return "", build
	}
	version := strings.Split(os.Version, ".")
	if len(version) != 3 || strings.Join(version, ".") != fmt.Sprintf("%d.%d.%d", b[0], b[1], b[2]) {
		return "", build
	}
	arch := map[string]string{"x64": "x64", "amd64": "x64", "x86_64": "x64", "arm64": "arm64", "aarch64": "arm64", "x86": "x86"}[strings.ToLower(os.Architecture)]
	if arch == "" {
		return "", build
	}
	if strings.Contains(os.Name, "Windows Server") && strings.HasPrefix(os.Edition, "Server") {
		year := map[uint64]string{9200: "2012", 9600: "2012_r2", 14393: "2016", 17763: "2019", 20348: "2022", 26100: "2025"}[b[2]]
		if year == "" || arch != "x64" || !strings.Contains(strings.ToLower(os.Name), strings.ReplaceAll(year, "_", " ")) {
			return "", build
		}
		kind := map[string]string{"Server": "server", "Server Core": "core"}[os.InstallationType]
		if kind == "" {
			return "", build
		}
		return "windows_server_" + year + "|x64|" + kind, build
	}
	if b[0] != 10 || b[1] != 0 {
		return "", build
	}
	editions := map[string]bool{"Professional": true, "ProfessionalN": true, "ProfessionalEducation": true, "ProfessionalWorkstation": true, "Enterprise": true, "EnterpriseN": true, "EnterpriseS": true, "EnterpriseSN": true, "Education": true, "EducationN": true, "Core": true, "CoreN": true, "CoreSingleLanguage": true, "CoreCountrySpecific": true}
	if !editions[os.Edition] {
		return "", build
	}
	releases := map[uint64]string{10240: "10_1507", 10586: "10_1511", 14393: "10_1607", 15063: "10_1703", 16299: "10_1709", 17134: "10_1803", 17763: "10_1809", 18362: "10_1903", 18363: "10_1909", 19041: "10_2004", 19042: "10_20h2", 19043: "10_21h1", 19044: "10_21h2", 19045: "10_22h2", 22000: "11_21h2", 22621: "11_22h2", 22631: "11_23h2", 26100: "11_24h2", 26200: "11_25h2", 26300: "11_26h2", 28000: "11_26h1"}
	family := releases[b[2]]
	if family == "" || !strings.Contains(os.Name, "Windows "+strings.Split(family, "_")[0]) {
		return "", build
	}
	if os.Release != "" && !strings.EqualFold(os.Release, strings.Split(family, "_")[1]) {
		return "", build
	}
	return "windows_" + family + "|" + arch + "|client", build
}
func parseMicrosoft(data []byte, id string) (microsoftDocument, []microsoftEntry, error) {
	meta := microsoftDocument{ID: id}
	var doc struct {
		DocumentTracking struct {
			Identification     struct{ ID microsoftText }
			CurrentReleaseDate string
		}
		ProductTree   struct{ FullProductName []microsoftProduct }
		Vulnerability []struct {
			CVE             string
			Title           microsoftText
			ProductStatuses []struct {
				Type      int
				ProductID []string
			}
			CVSSScoreSets []struct {
				BaseScore float64
				Vector    string
				ProductID []string
			}
			Remediations []struct {
				Type                              int
				ProductID                         []string
				Description                       microsoftText
				Supercedence, FixedBuild, SubType string
			}
		}
	}
	if len(data) > 64<<20 || !microsoftDocID.MatchString(id) {
		return meta, nil, fmt.Errorf("invalid MSRC document bound/ID")
	}
	if e := json.Unmarshal(data, &doc); e != nil {
		return meta, nil, e
	}
	meta.Modified = microsoftTime(doc.DocumentTracking.CurrentReleaseDate)
	if doc.DocumentTracking.Identification.ID.Value != id || meta.Modified.IsZero() || meta.Modified.After(time.Now().Add(24*time.Hour)) || len(doc.ProductTree.FullProductName) > 10000 || len(doc.Vulnerability) > 30000 || len(doc.Vulnerability) == 0 {
		return meta, nil, fmt.Errorf("unexpected MSRC CVRF document identity/structure")
	}
	products := map[string]microsoftProduct{}
	for _, p := range doc.ProductTree.FullProductName {
		if productTarget(p) != "" {
			if _, ok := products[p.ProductID]; ok {
				return meta, nil, fmt.Errorf("duplicate MSRC product")
			}
			products[p.ProductID] = p
		}
	}
	out := []microsoftEntry{}
	for _, v := range doc.Vulnerability {
		if !cveID.MatchString(v.CVE) || len(v.Title.Value) > 4096 {
			continue
		}
		for _, status := range v.ProductStatuses {
			if status.Type != 3 && status.Type != 4 {
				continue
			}
			for _, pid := range status.ProductID {
				p, ok := products[pid]
				if !ok {
					continue
				}
				base := microsoftEntry{CVE: v.CVE, Title: v.Title.Value, Product: p.Value, ProductID: pid, Target: productTarget(p), Severity: "unknown", KnownNotAffected: status.Type == 4}
				for _, score := range v.CVSSScoreSets {
					if len(score.ProductID) == 0 || containsMSRC(score.ProductID, pid) {
						if score.BaseScore >= 0 && score.BaseScore <= 10 && score.BaseScore > base.Score {
							base.Score = score.BaseScore
							base.Vector = score.Vector
							base.Severity = Severity(base.Score)
						}
					}
				}
				if base.KnownNotAffected {
					out = append(out, base)
					continue
				}
				found := false
				for _, r := range v.Remediations {
					if r.Type != 2 || !containsMSRC(r.ProductID, pid) {
						continue
					}
					item := base
					item.KB = kb(r.Description.Value)
					item.FixedBuild = r.FixedBuild
					if _, ok := windowsBuild(item.FixedBuild); !ok {
						item.FixedBuild = ""
					}
					parts := strings.FieldsFunc(r.Supercedence, func(r rune) bool { return r == ',' || r == ';' || r == ' ' })
					for _, part := range parts {
						value := kb(part)
						if value == "" {
							item.Supersedes = nil
							break
						}
						item.Supersedes = append(item.Supersedes, value)
					}
					if item.KB != "" || item.FixedBuild != "" {
						out = append(out, item)
						found = true
					}
				}
				if !found {
					out = append(out, base)
				}
			}
		}
	}
	if len(out) > 100000 {
		return meta, nil, fmt.Errorf("MSRC findings exceed bound")
	}
	meta.Records = len(out)
	sum := sha256.Sum256(data)
	meta.SHA256 = hex.EncodeToString(sum[:])
	return meta, out, nil
}
func containsMSRC(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func fetchMicrosoft(ctx context.Context, path string, limit int64) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", MicrosoftSource+path, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Cerber/1 MSRC CVRF")
	resp, e := microsoftClient.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("MSRC HTTP %d", resp.StatusCode)
	}
	data, e := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if e == nil && int64(len(data)) > limit {
		e = fmt.Errorf("MSRC response exceeds bound")
	}
	return data, e
}
func (c *Catalog) microsoftState(ctx context.Context) MicrosoftStatus {
	var text string
	var v MicrosoftStatus
	if c.db.QueryRowContext(ctx, "SELECT payload FROM metadata WHERE id='msrc' ").Scan(&text) == nil {
		json.Unmarshal([]byte(text), &v)
	}
	return v
}
func (c *Catalog) saveMicrosoftState(ctx context.Context, v MicrosoftStatus) {
	p, _ := json.Marshal(v)
	c.db.ExecContext(ctx, "INSERT INTO metadata VALUES('msrc',?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", string(p))
}
func (c *Catalog) MicrosoftStatus(ctx context.Context) MicrosoftStatus {
	v := c.microsoftState(ctx)
	v.Scope = "MSRC CVRF: Windows 10/11 и Windows Server 2012–2025, документы с 2016 года; отсутствие записи не доказывает отсутствие уязвимостей"
	v.Busy = c.microsoftBusy.Load()
	c.db.QueryRowContext(ctx, "SELECT count(*) FROM msrc_documents WHERE json_extract(payload,'$.at')>'2000'").Scan(&v.Documents)
	c.db.QueryRowContext(ctx, "SELECT coalesce(sum(json_extract(payload,'$.records')),0) FROM msrc_documents").Scan(&v.Records)
	var errors int
	c.db.QueryRowContext(ctx, "SELECT count(*) FROM msrc_documents WHERE coalesce(json_extract(payload,'$.error'),'')<>''").Scan(&errors)
	v.Errors = errors
	v.InitialComplete = v.Expected > 0 && v.Documents == v.Expected && errors == 0 && v.Error == ""
	v.Releases = nil
	return v
}

// SyncMicrosoft imports two monthly documents per pass, newest first. Compact
// entries replace a document atomically; failures retain its previous data.
func (c *Catalog) SyncMicrosoft(ctx context.Context) {
	if !c.microsoftBusy.CompareAndSwap(false, true) {
		return
	}
	defer c.microsoftBusy.Store(false)
	now := time.Now().UTC()
	state := c.microsoftState(ctx)
	force := c.microsoftForce.Swap(false)
	if force || state.At.IsZero() || now.Sub(state.Attempt) > time.Hour {
		state.Attempt = now
		data, e := fetchMicrosoft(ctx, "updates", 4<<20)
		if e == nil {
			var releases []microsoftRelease
			if len(data) > 0 && data[0] == '[' {
				e = json.Unmarshal(data, &releases)
			} else {
				var wrapped struct {
					Value []microsoftRelease `json:"value"`
				}
				e = json.Unmarshal(data, &wrapped)
				releases = wrapped.Value
			}
			if e == nil && len(releases) > 0 && len(releases) < 2000 {
				selected := []microsoftRelease{}
				seen := map[string]bool{}
				for _, r := range releases {
					t, err := time.Parse("2006-Jan", r.ID)
					release := microsoftTime(r.InitialReleaseDate)
					if err != nil || t.Year() < 2016 || t.After(now) || release.After(now) || !microsoftDocID.MatchString(r.ID) {
						continue
					}
					if seen[r.ID] {
						e = fmt.Errorf("duplicate MSRC release")
						break
					}
					seen[r.ID] = true
					selected = append(selected, r)
				}
				if e == nil && len(selected) > 0 {
					state.Releases = selected
					state.Expected = len(selected)
					state.At = now
					state.Error = ""
				} else if e == nil {
					e = fmt.Errorf("empty MSRC release scope")
				}
			} else if e == nil {
				e = fmt.Errorf("invalid MSRC release index")
			}
		}
		if e != nil {
			state.Error = e.Error()
		}
		c.saveMicrosoftState(ctx, state)
	}
	if len(state.Releases) == 0 {
		return
	}
	sort.Slice(state.Releases, func(i, j int) bool {
		a, _ := time.Parse("2006-Jan", state.Releases[i].ID)
		b, _ := time.Parse("2006-Jan", state.Releases[j].ID)
		return a.After(b)
	})
	attempted := 0
	for _, r := range state.Releases {
		if ctx.Err() != nil || attempted >= 2 {
			return
		}
		var prior microsoftDocument
		var p string
		if c.db.QueryRowContext(ctx, "SELECT payload FROM msrc_documents WHERE id=?", r.ID).Scan(&p) == nil {
			json.Unmarshal([]byte(p), &prior)
		}
		if !force && !prior.Attempt.IsZero() && now.Sub(prior.Attempt) < time.Hour {
			continue
		}
		if !force && !prior.At.IsZero() && !microsoftTime(r.CurrentReleaseDate).After(prior.Modified) && now.Sub(prior.At) < 7*24*time.Hour {
			continue
		}
		available, _, _, e := health.DiskSpace(filepath.Dir(c.path))
		if e != nil || available < 3<<30+64<<20 {
			state.Error = "Недостаточно свободного места для импорта MSRC (нужен резерв 3 ГиБ + 64 МиБ)"
			c.saveMicrosoftState(ctx, state)
			return
		}
		attempted++
		data, e := fetchMicrosoft(ctx, "cvrf/"+r.ID, 64<<20)
		var meta microsoftDocument
		var entries []microsoftEntry
		if e == nil {
			meta, entries, e = parseMicrosoft(data, r.ID)
		}
		if e == nil {
			meta.At = now
			meta.Attempt = now
			payload, _ := json.Marshal(meta)
			tx, err := c.db.BeginTx(ctx, nil)
			if err != nil {
				return
			}
			_, err = tx.ExecContext(ctx, "DELETE FROM msrc_entries WHERE document=?", r.ID)
			groups := map[string][]microsoftEntry{}
			for _, item := range entries {
				groups[item.Target] = append(groups[item.Target], item)
			}
			keys := []string{}
			for key := range groups {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for n, key := range keys {
				if err != nil {
					break
				}
				encoded, encodeErr := encodeMicrosoftEntries(groups[key])
				if encodeErr != nil {
					err = encodeErr
					break
				}
				_, err = tx.ExecContext(ctx, "INSERT INTO msrc_entries VALUES(?,?,?,?,?)", r.ID, n, "", key, encoded)
			}
			if err == nil {
				_, err = tx.ExecContext(ctx, "INSERT INTO msrc_documents VALUES(?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", r.ID, string(payload))
			}
			var size int64
			if err == nil {
				err = tx.QueryRowContext(ctx, "SELECT coalesce(sum(length(payload)),0) FROM msrc_entries").Scan(&size)
				if size > 256<<20 {
					err = fmt.Errorf("MSRC compact cache exceeds 256 MiB")
				}
			}
			if err == nil {
				err = tx.Commit()
			} else {
				tx.Rollback()
			}
			e = err
		}
		if e != nil {
			prior.ID = r.ID
			prior.Attempt = now
			prior.Error = e.Error()
			payload, _ := json.Marshal(prior)
			c.db.ExecContext(ctx, "INSERT INTO msrc_documents VALUES(?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", r.ID, string(payload))
		}
	}
}

func (c *Catalog) WindowsInventory(ctx context.Context, snap inventory.Snapshot, offset, limit int) (WindowsReport, error) {
	return c.windowsInventory(ctx, snap, offset, limit, "")
}
func (c *Catalog) windowsInventory(ctx context.Context, snap inventory.Snapshot, offset, limit int, onlyCVE string) (WindowsReport, error) {
	report := WindowsReport{SnapshotID: snap.ID, OS: snap.OS, Source: c.MicrosoftStatus(ctx), Status: "unknown", Counts: map[string]int{"affected": 0, "fixed": 0, "unknown": 0}, Items: []WindowsFinding{}}
	target, build := snapshotWindowsTarget(snap)
	if strings.ToLower(snap.OS.Family) != "windows" {
		report.Status = "unsupported"
		report.Reason = "Проверка MSRC предназначена для Windows"
		return report, nil
	}
	if target == "" {
		report.Reason = "Не определены поддерживаемые выпуск, редакция, архитектура и полная сборка Windows; для Server требуется тип установки"
		return report, nil
	}
	now := time.Now().UTC()
	fresh := snap.CoverageStatus("os") == "complete" && !snap.CollectedAt.IsZero() && now.Sub(snap.CollectedAt) <= 24*time.Hour && !snap.CollectedAt.After(now.Add(5*time.Minute))
	if offset < 0 || limit < 1 || limit > 100 {
		return report, fmt.Errorf("invalid Windows report pagination")
	}
	rows, e := c.db.QueryContext(ctx, `SELECT e.document,e.payload,d.payload FROM msrc_entries e JOIN msrc_documents d ON d.id=e.document WHERE e.target=? ORDER BY e.document,e.ordinal`, target)
	if e != nil {
		return report, e
	}
	type sourceEntry struct {
		entry microsoftEntry
		meta  microsoftDocument
		order time.Time
	}
	all := []sourceEntry{}
	latest := map[string]time.Time{}
	for rows.Next() {
		var id, meta string
		var p []byte
		if e = rows.Scan(&id, &p, &meta); e != nil {
			break
		}
		items, decodeErr := decodeMicrosoftEntries(p)
		if decodeErr != nil {
			e = decodeErr
			break
		}
		var m microsoftDocument
		if e = json.Unmarshal([]byte(meta), &m); e != nil {
			break
		}
		order, _ := time.Parse("2006-Jan", id)
		for _, item := range items {
			if item.Target != target {
				e = fmt.Errorf("MSRC cache product identity mismatch")
				break
			}
			v := sourceEntry{entry: item, meta: m, order: order}
			all = append(all, v)
			if v.order.After(latest[v.entry.CVE]) {
				latest[v.entry.CVE] = v.order
			}
		}
		if e != nil {
			break
		}
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return report, e
	}
	state := c.microsoftState(ctx)
	versions := map[string]time.Time{}
	for _, r := range state.Releases {
		versions[r.ID] = microsoftTime(r.CurrentReleaseDate)
	}
	validSource := func(m microsoftDocument) bool {
		return !m.At.IsZero() && m.Error == "" && !state.At.IsZero() && now.Sub(state.At) <= 48*time.Hour && state.Error == "" && !versions[m.ID].IsZero() && !versions[m.ID].After(m.Modified)
	}
	installed := map[string]bool{}
	for _, u := range snap.Updates {
		for _, id := range u.KBs {
			if k := kb(id); k != "" {
				if u.State == "installed" && u.Source == "windows-update-agent-local-cache" {
					installed[k] = true
				}

			}
		}
	}
	// Edges have a product identity and an explicit Microsoft successor -> predecessor
	// direction. Never infer replacement from a larger KB number or another product.
	graph := map[string][]string{}
	for _, v := range all {
		if validSource(v.meta) && v.entry.KB != "" {
			graph[v.entry.KB] = append(graph[v.entry.KB], v.entry.Supersedes...)
		}
	}
	replacement := func(fix string) (string, []string) {
		keys := []string{}
		for k := range installed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, root := range keys {
			type node struct {
				k    string
				path []string
			}
			q := []node{{root, []string{root}}}
			seen := map[string]bool{}
			for len(q) > 0 && len(seen) < 256 {
				n := q[0]
				q = q[1:]
				if seen[n.k] {
					continue
				}
				seen[n.k] = true
				if n.k == fix {
					return root, n.path
				}
				if len(n.path) >= 32 {
					continue
				}
				for _, next := range graph[n.k] {
					q = append(q, node{next, append(append([]string{}, n.path...), next)})
				}
			}
		}
		return "", nil
	}
	grouped := map[string][]sourceEntry{}
	for _, v := range all {
		if v.order.Equal(latest[v.entry.CVE]) {
			grouped[v.entry.CVE] = append(grouped[v.entry.CVE], v)
		}
	}
	results := []WindowsFinding{}
	for id, entries := range grouped {
		if onlyCVE != "" && id != onlyCVE {
			continue
		}
		states := []WindowsFinding{}
		for _, v := range entries {
			x := v.entry
			a := PackageAssessment{Status: "unknown", AgentID: "", SnapshotID: snap.ID, CollectedAt: snap.CollectedAt, CheckedAt: now, CVE: id, Rule: "microsoft-cvrf-windows/1", Release: snap.OS.Release, SourceName: "Microsoft MSRC · CVRF 3.0", SourceURL: MicrosoftSource + "cvrf/" + v.meta.ID, SourceModified: v.meta.Modified, SourceFetched: v.meta.At, SourceSHA256: v.meta.SHA256, Packages: []PackageEvidence{}}
			f := WindowsFinding{Record: Record{ID: id, Title: x.Title, Source: "Microsoft MSRC", URL: "https://msrc.microsoft.com/update-guide/vulnerability/" + id, Score: x.Score, Severity: x.Severity, Vector: x.Vector, CVEs: []string{id}}, Assessment: a, Windows: WindowsEvidence{Product: x.Product, ProductID: x.ProductID, InstalledBuild: build, FixedBuild: x.FixedBuild, KB: x.KB}}
			f.Assessment.Reason = "Microsoft не опубликовал однозначную границу исправленной сборки; отсутствие KB в частичном WUA не доказывает уязвимость"
			if !fresh {
				f.Assessment.Reason = "Нужен полный свежий снимок ОС (не старше суток)"
			} else if !validSource(v.meta) {
				f.Assessment.Reason = "Источник MSRC устарел, изменён или недоступен; требуется успешная синхронизация"
			} else if x.KnownNotAffected {
				f.Assessment.Status = "fixed"
				f.Assessment.Reason = "Microsoft указывает, что этот продукт не затронут (Known Not Affected)"
			} else {
				installedKB, path := replacement(x.KB)
				f.Windows.InstalledKB = installedKB
				f.Windows.Supersedence = path
				current, _ := windowsBuild(build)
				fixed, valid := windowsBuild(x.FixedBuild)
				if valid && current[0] == fixed[0] && current[1] == fixed[1] && current[2] == fixed[2] {
					if current[3] >= fixed[3] {
						f.Assessment.Status = "fixed"
						f.Assessment.Reason = "Сборка ОС достигла опубликованной Microsoft границы исправления в той же ветке"
					} else if installedKB != "" {
						f.Assessment.Reason = "Исправляющий или заменяющий KB установлен, но сборка ниже исправленной: проверьте необходимость перезагрузки и повторите инвентаризацию"
					} else {
						f.Assessment.Status = "affected"
						f.Assessment.Reason = "Сборка ОС ниже исправленной по MSRC; условия эксплуатации и состояние отдельных компонентов требуют проверки"
					}
				} else if valid {
					f.Assessment.Reason = "Ветка исправленной сборки не совпадает с инвентарём; автоматическое сравнение запрещено"
				} else if installedKB != "" {
					f.Assessment.Reason = "WUA подтверждает установку исправляющего KB или его явно опубликованной замены; перезагрузка и фактическая активация исправления требуют проверки"
				}
			}
			if f.Assessment.Status == "fixed" && !x.KnownNotAffected && (snap.OS.RebootRequired == nil || *snap.OS.RebootRequired) {
				f.Assessment.Status = "unknown"
				f.Assessment.Reason = "Исправление установлено, но завершение перезагрузки не подтверждено; повторите инвентаризацию после перезагрузки"
			}
			states = append(states, f)
		}
		// A CVE can have alternative rollup/security-only remediations. A valid fixed
		// alternative suffices; contradictory KnownNotAffected and affected evidence does not.
		chosen := states[0]
		hasFixed, hasAffected, hasUnknown, notAffected := false, false, false, false
		for _, f := range states {
			switch f.Assessment.Status {
			case "fixed":
				if !hasFixed {
					chosen = f
				}
				hasFixed = true
			case "affected":
				if !hasFixed {
					chosen = f
				}
				hasAffected = true
			default:
				hasUnknown = true
			}
			notAffected = notAffected || strings.Contains(f.Assessment.Reason, "Known Not Affected")
		}
		if notAffected && hasAffected {
			chosen.Assessment.Status = "unknown"
			chosen.Assessment.Reason = "Противоречивые статусы продукта в MSRC"
		} else if !hasFixed && hasAffected && hasUnknown {
			chosen.Assessment.Status = "unknown"
			chosen.Assessment.Reason = "Не все альтернативные исправления можно проверить; требуется уточнение"
		}
		report.Counts[chosen.Assessment.Status]++
		results = append(results, chosen)
	}
	sort.Slice(results, func(i, j int) bool {
		rank := map[string]int{"affected": 0, "unknown": 1, "fixed": 2}
		a, b := results[i], results[j]
		if rank[a.Assessment.Status] != rank[b.Assessment.Status] {
			return rank[a.Assessment.Status] < rank[b.Assessment.Status]
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.ID < b.ID
	})
	report.Total = len(results)
	if offset < len(results) {
		end := offset + limit
		if end > len(results) {
			end = len(results)
		}
		report.Items = results[offset:end]
	}
	report.Status = "ready"
	report.Reason = "Проверены только опубликованные записи для точного продукта; отсутствие совпадений не означает безопасность ОС. После установки обновлений выполните новый сбор инвентаря."
	if !fresh {
		report.Status = "unknown"
		report.Reason = "Нужен полный свежий снимок ОС"
	} else if len(results) == 0 {
		report.Status = "unknown"
		report.Reason = "Для продукта пока нет загруженных записей MSRC; дождитесь синхронизации каталога"
	}
	return report, nil
}

func (c *Catalog) RequestMicrosoft() { c.microsoftForce.Store(true) }

func (c *Catalog) AssessWindows(ctx context.Context, m Match, b InventoryBinding, now time.Time) PackageAssessment {
	a := unknownAssessment(b, now, "Для CVE нет точной записи MSRC по продукту Windows")
	a.Rule = "microsoft-cvrf-windows/1"
	if b.Link.State != "linked" {
		a.Reason = b.Link.Reason
		return a
	}
	ids := append([]string{m.ID}, m.CVEs...)
	for _, id := range ids {
		if !cveID.MatchString(id) {
			continue
		}
		r, e := c.windowsInventory(ctx, b.Snapshot, 0, 1, id)
		if e != nil || len(r.Items) == 0 {
			continue
		}
		v := r.Items[0]
		a = v.Assessment
		a.AgentID = b.Link.AgentID
		a.Windows = &v.Windows
		return a
	}
	return a
}

// One compressed chunk per product/month keeps historical CVRF data compact.
// The catalog never caches the large upstream CVRF documents themselves.
func encodeMicrosoftEntries(items []microsoftEntry) ([]byte, error) {
	p, e := json.Marshal(items)
	if e != nil {
		return nil, e
	}
	if len(p) > 32<<20 {
		return nil, fmt.Errorf("MSRC product chunk exceeds bound")
	}
	var b bytes.Buffer
	z, e := gzip.NewWriterLevel(&b, gzip.BestSpeed)
	if e != nil {
		return nil, e
	}
	if _, e = z.Write(p); e != nil {
		return nil, e
	}
	if e = z.Close(); e != nil {
		return nil, e
	}
	return b.Bytes(), nil
}
func decodeMicrosoftEntries(p []byte) ([]microsoftEntry, error) {
	if len(p) > 32<<20 {
		return nil, fmt.Errorf("MSRC cache chunk exceeds bound")
	}
	if len(p) > 2 && p[0] == 0x1f && p[1] == 0x8b {
		z, e := gzip.NewReader(bytes.NewReader(p))
		if e != nil {
			return nil, e
		}
		data, e := io.ReadAll(io.LimitReader(z, (32<<20)+1))
		z.Close()
		if e != nil {
			return nil, e
		}
		if len(data) > 32<<20 {
			return nil, fmt.Errorf("MSRC inflated chunk exceeds bound")
		}
		p = data
	}
	var out []microsoftEntry
	if len(p) > 0 && p[0] == '{' {
		var v microsoftEntry
		if e := json.Unmarshal(p, &v); e != nil {
			return nil, e
		}
		return []microsoftEntry{v}, nil
	}
	e := json.Unmarshal(p, &out)
	if e == nil && len(out) > 100000 {
		e = fmt.Errorf("MSRC chunk record count exceeds bound")
	}
	return out, e
}

func validMicrosoftCPE(raw, family, arch string) bool {
	p := strings.Split(strings.ToLower(raw), ":")
	if len(p) != 13 || strings.Join(p[:5], ":") != "cpe:2.3:o:microsoft:"+family {
		return false
	}
	return p[11] == "*" || p[11] == arch
}
