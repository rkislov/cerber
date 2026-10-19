// SPDX-License-Identifier: Apache-2.0
package linux

import (
	"bufio"
	"fmt"
	"github.com/rkislov/cerber/internal/inventory"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var instLine = regexp.MustCompile(`^Inst\s+(\S+)(?:\s+\[([^\]]+)\])?\s+\((\S+)(?:\s+(.*))?\)(?:\s+\[[^\]]*\])?\s*$`)
var archTail = regexp.MustCompile(`\[([a-zA-Z0-9_+-]+)\]\s*$`)
var summaryLine = regexp.MustCompile(`(?m)^\d+ upgraded,`)
var sourceURL = regexp.MustCompile(`https?://[^\s]+`)

func sanitizeOrigin(v string) string {
	v = sourceURL.ReplaceAllStringFunc(v, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			return "[repository]"
		}
		u.User = nil
		u.RawQuery = ""
		u.Fragment = ""
		return u.String()
	})
	if len(v) > 1024 {
		return "[repository origin exceeds display limit]"
	}
	return v
}
func installedVersions(c inventory.Component) []string {
	if len(c.InstalledVersions) > 0 {
		return c.InstalledVersions
	}
	return []string{c.Version}
}
func sameEVR(a, b, scheme string) bool {
	if scheme == "rpm" {
		a = strings.TrimPrefix(a, "0:")
		b = strings.TrimPrefix(b, "0:")
	}
	return a == b
}
func makeUpdate(c inventory.Component, version, repository, source string) inventory.Update {
	return inventory.Update{ID: c.ID, Title: c.Name, State: "available", Source: source, InstalledVersion: c.Version, InstalledVersions: c.InstalledVersions, AvailableVersion: version, Architecture: c.Architecture, Repository: sanitizeOrigin(repository), VersionScheme: c.VersionScheme, KBs: []string{}}
}
func sortedUpdates(values map[string]inventory.Update) []inventory.Update {
	result := []inventory.Update{}
	for _, v := range values {
		result = append(result, v)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

// APT's solver, not lexical/SemVer comparison, selects candidate versions. New
// dependencies and removals are deliberately not labelled as installed-package updates.
func parseAPT(data, source string, index packageIndex) ([]inventory.Update, error) {
	if !summaryLine.MatchString(data) {
		return nil, fmt.Errorf("APT simulation summary not recognized")
	}
	values := map[string]inventory.Update{}
	scan := bufio.NewScanner(strings.NewReader(data))
	scan.Buffer(make([]byte, 4096), 1<<20)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		m := instLine.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("APT simulation record not recognized")
		}
		name, old, candidate, origin := m[1], m[2], m[3], m[4]
		// No prior installed version: this is a dependency/new install, not an upgrade observation.
		if old == "" {
			continue
		}
		var arch string
		if pos := strings.LastIndex(name, ":"); pos >= 0 {
			arch = name[pos+1:]
			name = name[:pos]
		}
		if a := archTail.FindStringSubmatch(origin); a != nil {
			if arch != "" && arch != a[1] {
				return nil, fmt.Errorf("APT architecture replacement is not modelled")
			}
			arch = a[1]
		}
		ids := index.ByName[name]
		matched := []inventory.Component{}
		for _, id := range ids {
			c := index.ByID[id]
			if arch != "" && c.Architecture != arch {
				continue
			}
			for _, v := range installedVersions(c) {
				if sameEVR(strings.TrimSuffix(old, ":"+c.Architecture), v, index.Scheme) {
					matched = append(matched, c)
					break
				}
			}
		}
		if len(matched) != 1 {
			return nil, fmt.Errorf("APT upgrade cannot be bound to one installed package/architecture")
		}
		c := matched[0]
		if len(candidate) > 512 {
			return nil, fmt.Errorf("candidate version too long")
		}
		if index.Scheme == "rpm" && !strings.Contains(candidate, ":") {
			candidate = "0:" + candidate
		}
		if sameEVR(candidate, old, index.Scheme) {
			continue
		}
		u := makeUpdate(c, candidate, origin, source)
		if _, exists := values[c.ID]; exists {
			return nil, fmt.Errorf("duplicate APT upgrade candidate")
		}
		values[c.ID] = u
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}
	return sortedUpdates(values), nil
}
func parseRPMUpdates(data, source string, index packageIndex) ([]inventory.Update, error) {
	values := map[string]inventory.Update{}
	scan := bufio.NewScanner(strings.NewReader(data))
	scan.Buffer(make([]byte, 4096), 1<<20)
	obsoletes := false
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Obsoleting Packages") {
			obsoletes = true
			continue
		}
		if obsoletes {
			continue
		}
		if strings.HasPrefix(line, "Last metadata expiration check:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("RPM frontend update row not recognized")
		}
		dot := strings.LastIndex(fields[0], ".")
		if dot < 1 {
			return nil, fmt.Errorf("RPM update row lacks architecture")
		}
		name, arch := fields[0][:dot], fields[0][dot+1:]
		c, ok := index.ByID[componentID("rpm", name, arch)]
		if !ok {
			return nil, fmt.Errorf("RPM candidate not bound to an installed package")
		}
		candidate := fields[1]
		if !strings.Contains(candidate, ":") {
			candidate = "0:" + candidate
		}
		if len(candidate) > 512 {
			return nil, fmt.Errorf("candidate version too long")
		}
		if _, exists := values[c.ID]; exists {
			return nil, fmt.Errorf("multiple RPM candidates for one package")
		}
		values[c.ID] = makeUpdate(c, candidate, fields[2], source)
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}
	return sortedUpdates(values), nil
}
