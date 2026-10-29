// SPDX-License-Identifier: Apache-2.0
package vuln

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/inventory"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

var ubuntuClient = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

const UbuntuSource = "https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main/osv/cve/"

type UbuntuOSV struct {
	SchemaVersion string           `json:"schema_version"`
	ID            string           `json:"id"`
	Modified      time.Time        `json:"modified"`
	Withdrawn     *time.Time       `json:"withdrawn,omitempty"`
	Upstream      []string         `json:"upstream"`
	Affected      []UbuntuAffected `json:"affected"`
}
type UbuntuAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced   string `json:"introduced,omitempty"`
			Fixed        string `json:"fixed,omitempty"`
			LastAffected string `json:"last_affected,omitempty"`
			Limit        string `json:"limit,omitempty"`
		} `json:"events"`
	} `json:"ranges"`
	EcosystemSpecific struct {
		Binaries []struct {
			Name    string `json:"binary_name"`
			Version string `json:"binary_version"`
		} `json:"binaries"`
		Availability string `json:"availability"`
	} `json:"ecosystem_specific"`
}
type UbuntuCache struct {
	Record  UbuntuOSV `json:"record"`
	At      time.Time `json:"at"`
	Attempt time.Time `json:"attempt"`
	Error   string    `json:"error,omitempty"`
	SHA256  string    `json:"sha256"`
	URL     string    `json:"url"`
}
type PackageEvidence struct {
	Name          string `json:"name"`
	Architecture  string `json:"architecture"`
	Installed     string `json:"installed"`
	SourcePackage string `json:"source_package"`
	SourceVersion string `json:"source_version"`
	Fixed         string `json:"fixed"`
	Status        string `json:"status"`
}
type PackageAssessment struct {
	Windows        *WindowsEvidence  `json:"windows,omitempty"`
	SourceName     string            `json:"source_name,omitempty"`
	Definitions    []string          `json:"definitions,omitempty"`
	Status         string            `json:"status"`
	Reason         string            `json:"reason"`
	AgentID        string            `json:"agent_id,omitempty"`
	SnapshotID     string            `json:"snapshot_id,omitempty"`
	CollectedAt    time.Time         `json:"collected_at,omitempty"`
	CheckedAt      time.Time         `json:"checked_at"`
	CVE            string            `json:"cve,omitempty"`
	Release        string            `json:"release,omitempty"`
	SourceURL      string            `json:"source_url,omitempty"`
	SourceModified time.Time         `json:"source_modified,omitempty"`
	SourceFetched  time.Time         `json:"source_fetched,omitempty"`
	SourceSHA256   string            `json:"source_sha256,omitempty"`
	Packages       []PackageEvidence `json:"packages"`
	Rule           string            `json:"rule"`
}
type InventoryLink struct {
	State       string       `json:"state"`
	Reason      string       `json:"reason"`
	AgentID     string       `json:"agent_id,omitempty"`
	SnapshotID  string       `json:"snapshot_id,omitempty"`
	CollectedAt time.Time    `json:"collected_at,omitempty"`
	OS          inventory.OS `json:"os"`
}
type InventoryBinding struct {
	Link     InventoryLink
	Snapshot inventory.Snapshot
}
type InventorySource interface {
	VulnerabilityInventory(context.Context, string) (InventoryBinding, error)
}

func ubuntuURL(id string) string {
	return UbuntuSource + strings.Split(id, "-")[1] + "/UBUNTU-" + id + ".json"
}
func (c *Catalog) ubuntuCache(ctx context.Context, id string) UbuntuCache {
	var p string
	var v UbuntuCache
	if c.db.QueryRowContext(ctx, "SELECT payload FROM ubuntu_osv WHERE cve=?", id).Scan(&p) == nil {
		json.Unmarshal([]byte(p), &v)
	}
	return v
}
func parseUbuntu(data []byte, id string) (UbuntuOSV, error) {
	var v UbuntuOSV
	if !cveID.MatchString(id) || len(data) > 4<<20 {
		return v, fmt.Errorf("invalid Ubuntu record")
	}
	if e := json.Unmarshal(data, &v); e != nil {
		return v, e
	}
	if v.ID != "UBUNTU-"+id || v.Modified.IsZero() || v.Modified.After(time.Now().Add(24*time.Hour)) || len(v.Affected) > 500 || len(v.Affected) == 0 || !strings.HasPrefix(v.SchemaVersion, "1.") {
		return v, fmt.Errorf("unexpected Ubuntu OSV identity/schema")
	}
	for _, a := range v.Affected {
		if len(a.EcosystemSpecific.Binaries) > 10000 || len(a.Ranges) > 100 {
			return v, fmt.Errorf("Ubuntu OSV record exceeds bounds")
		}
	}
	return v, nil
}

// SyncUbuntu downloads only CVEs observed in managed network findings. Missing
// records and unsupported releases never establish absence of a vulnerability.
func (c *Catalog) SyncUbuntu(ctx context.Context, ids []string) {
	if !c.ubuntuBusy.CompareAndSwap(false, true) {
		return
	}
	defer c.ubuntuBusy.Store(false)
	force := c.ubuntuForce.Swap(false)
	unique := map[string]bool{}
	for _, id := range ids {
		if cveID.MatchString(id) {
			unique[id] = true
		}
	}
	keys := []string{}
	for id := range unique {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	count, failures := 0, 0
	for _, id := range keys {
		if ctx.Err() != nil {
			return
		}
		v := c.ubuntuCache(ctx, id)
		if !force && (v.Error == "" && !v.At.IsZero() && time.Since(v.At) < 24*time.Hour || time.Since(v.Attempt) < time.Hour) {
			continue
		}
		if count >= 64 {
			return
		}
		count++
		v.Attempt = time.Now().UTC()
		v.URL = ubuntuURL(id)
		req, e := http.NewRequestWithContext(ctx, "GET", v.URL, nil)
		if e != nil {
			return
		}
		req.Header.Set("User-Agent", "Cerber-SIEM/1")
		req.Header.Set("Accept", "application/json")
		resp, e := ubuntuClient.Do(req)
		stop := e != nil
		if e == nil && (resp.StatusCode == 429 || resp.StatusCode >= 500) {
			stop = true
		}
		if e == nil {
			var data []byte
			if resp.StatusCode != http.StatusOK {
				e = fmt.Errorf("Ubuntu OSV HTTP %d", resp.StatusCode)
			} else {
				data, e = io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
			}
			resp.Body.Close()
			if e == nil {
				var record UbuntuOSV
				record, e = parseUbuntu(data, id)
				if e == nil {
					v.Record = record
					v.At = time.Now().UTC()
					sum := sha256.Sum256(data)
					v.SHA256 = hex.EncodeToString(sum[:])
					v.Error = ""
				}
			}
		}
		if e != nil {
			v.Error = e.Error()
		}
		p, _ := json.Marshal(v)
		if _, e = c.db.ExecContext(ctx, "INSERT INTO ubuntu_osv VALUES(?,?) ON CONFLICT(cve) DO UPDATE SET payload=excluded.payload", id, string(p)); e != nil {
			return
		}
		if stop {
			failures++
		} else {
			failures = 0
		}
		if failures >= 3 || (resp != nil && resp.StatusCode == 429) {
			return
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func unknownAssessment(binding InventoryBinding, now time.Time, reason string) PackageAssessment {
	return PackageAssessment{Status: "unknown", Reason: reason, AgentID: binding.Link.AgentID, SnapshotID: binding.Link.SnapshotID, CollectedAt: binding.Link.CollectedAt, CheckedAt: now, Packages: []PackageEvidence{}, Rule: "ubuntu-osv-package/1"}
}

// Service package roles are deliberately explicit: having openssh-client does
// not prove that an observed SSH server is the distribution's openssh-server.
func servicePackages(cpe string) map[string]bool {
	fields := strings.Split(cpe, ":")
	if len(fields) != 13 {
		return nil
	}
	key := fields[3] + ":" + fields[4]
	names := map[string][]string{"openbsd:openssh": {"openssh-server"}, "apache:http_server": {"apache2-bin"}, "nginx:nginx": {"nginx", "nginx-core", "nginx-full", "nginx-light", "nginx-extras"}, "dovecot:dovecot": {"dovecot-core"}, "postfix:postfix": {"postfix"}, "openssl:openssl": {"libssl3", "libssl3t64", "libssl1.1"}, "exim:exim": {"exim4-daemon-heavy", "exim4-daemon-light"}}[key]
	out := map[string]bool{}
	for _, n := range names {
		out[n] = true
	}
	return out
}
func (c *Catalog) AssessUbuntu(ctx context.Context, m Match, binding InventoryBinding, now time.Time) PackageAssessment {
	v := unknownAssessment(binding, now, "Недостаточно данных для проверки пакета Ubuntu")
	if binding.Link.State != "linked" {
		v.Reason = binding.Link.Reason
		return v
	}
	snap := binding.Snapshot
	v.Release = snap.OS.Version
	if snap.OS.DistributionID != "ubuntu" || snap.PackageManager != "apt" {
		v.Reason = "Для этого дистрибутива адаптер производителя пока не подключён"
		return v
	}
	if snap.CollectedAt.IsZero() || now.Sub(snap.CollectedAt) > 24*time.Hour || snap.CollectedAt.After(now.Add(5*time.Minute)) {
		v.Reason = "Инвентарь старше суток либо время сбора недостоверно"
		return v
	}
	if snap.CoverageStatus("packages") != "complete" {
		v.Reason = "Нет полного снимка установленных пакетов"
		return v
	}
	roles := servicePackages(m.CPE)
	if len(roles) == 0 {
		v.Reason = "Не определена проверенная связь сервиса с бинарным пакетом"
		return v
	}
	ids := append([]string{m.ID}, m.CVEs...)
	sort.Strings(ids)
	seen := map[string]bool{}
	outcomes := []PackageAssessment{}
	for _, id := range ids {
		if !cveID.MatchString(id) || seen[id] {
			continue
		}
		seen[id] = true
		record := c.ubuntuCache(ctx, id)
		a := v
		a.CVE = id
		a.SourceURL = record.URL
		a.SourceFetched = record.At
		a.SourceModified = record.Record.Modified
		a.SourceSHA256 = record.SHA256
		if record.At.IsZero() || record.Error != "" || now.Sub(record.At) > 24*time.Hour || record.At.After(now.Add(5*time.Minute)) || record.Record.Withdrawn != nil {
			a.Reason = "Данные Ubuntu отсутствуют, устарели, отозваны или не удалось их обновить"
			outcomes = append(outcomes, a)
			continue
		}
		for _, affected := range record.Record.Affected {
			ecosystem := affected.Package.Ecosystem
			if ecosystem != "Ubuntu:"+snap.OS.Version && ecosystem != "Ubuntu:"+snap.OS.Version+":LTS" {
				continue
			}
			// Closed, single-introduction ranges are interpreted conservatively. Open
			// ranges also include needs-triage in Ubuntu OSV, so cannot confirm affected.
			if len(affected.Ranges) != 1 || affected.Ranges[0].Type != "ECOSYSTEM" || len(affected.Ranges[0].Events) != 2 {
				continue
			}
			events := affected.Ranges[0].Events
			if events[0].Introduced != "0" || events[0].Fixed != "" || events[0].Limit != "" || events[0].LastAffected != "" || events[1].Fixed == "" || events[1].Introduced != "" || events[1].LastAffected != "" || events[1].Limit != "" {
				continue
			}
			fixed := events[1].Fixed
			for _, component := range snap.Components {
				if !roles[component.Name] || component.Kind != "package" || component.State != "installed" || component.Source != "dpkg-query" || component.VersionScheme != "debian" || component.SourcePackage != affected.Package.Name || component.SourceVersion == "" {
					continue
				}
				knownBinary := false
				for _, binary := range affected.EcosystemSpecific.Binaries {
					if binary.Name == component.Name && binary.Version != "" {
						knownBinary = true
						break
					}
				}
				if !knownBinary {
					continue
				}
				comparison, e := CompareDebian(component.SourceVersion, fixed)
				if e != nil {
					continue
				}
				status := "affected"
				if comparison >= 0 {
					status = "fixed"
				}
				a.Packages = append(a.Packages, PackageEvidence{Name: component.Name, Architecture: component.Architecture, Installed: component.Version, SourcePackage: component.SourcePackage, SourceVersion: component.SourceVersion, Fixed: fixed, Status: status})
			}
		}
		if len(a.Packages) > 0 {
			a.Status = "fixed"
			for _, p := range a.Packages {
				if p.Status == "affected" {
					a.Status = "affected"
				}
			}
			a.Reason = "Сравнены версии исходного пакета из инвентаря и исправления Ubuntu с учётом epoch/revision. Это оценка установленного пакета, а не доказательство эксплуатации или версии работающего процесса."
		} else {
			a.Reason = "Для выпуска, роли сервиса и установленного пакета нет однозначного закрытого диапазона Ubuntu; отсутствие записи не доказывает исправление"
		}
		outcomes = append(outcomes, a)
	}
	// A BDU record may alias several CVEs. Do not declare it fixed unless every
	// associated CVE has a verified fixed package assessment.
	if len(outcomes) == 0 {
		return v
	}
	result := outcomes[0]
	if len(outcomes) > 1 {
		result = v
		result.Packages = []PackageEvidence{}
		result.Reason = "Запись связана с несколькими CVE; требуется индивидуальная проверка"
		return result
	}
	return result
}
