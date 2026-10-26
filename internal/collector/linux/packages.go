// SPDX-License-Identifier: Apache-2.0
package linux

import (
	"bufio"
	"fmt"
	"github.com/rkislov/cerber/internal/inventory"
	"sort"
	"strconv"
	"strings"
)

const dpkgFormat = "${Package}\t${Version}\t${Architecture}\t${Status}\t${source:Package}\t${source:Version}\n"
const rpmFormat = "%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n"

type packageIndex struct {
	ByID   map[string]inventory.Component
	ByName map[string][]string
	Scheme string
}

func componentID(scheme, name, arch string) string { return scheme + ":" + name + ":" + arch }
func packageText(v string) bool {
	if v == "" || len(v) > 256 || strings.HasPrefix(v, "-") {
		return false
	}
	for _, c := range v {
		if c <= 32 || c == 127 || c == ':' || c == '/' || c == '\\' {
			return false
		}
	}
	return true
}
func rpmEVR(epoch, version, release string) (string, error) {
	if epoch == "(none)" || epoch == "" {
		epoch = "0"
	}
	if _, err := strconv.ParseUint(epoch, 10, 64); err != nil {
		return "", fmt.Errorf("invalid RPM epoch")
	}
	if version == "" || release == "" || len(version)+len(release)+len(epoch) > 509 {
		return "", fmt.Errorf("invalid RPM version/release")
	}
	return epoch + ":" + version + "-" + release, nil
}
func parsePackages(data, scheme string) ([]inventory.Component, packageIndex, error) {
	index := packageIndex{ByID: map[string]inventory.Component{}, ByName: map[string][]string{}, Scheme: scheme}
	versions := map[string]map[string]bool{}
	scan := bufio.NewScanner(strings.NewReader(data))
	scan.Buffer(make([]byte, 4096), 1<<20)
	for scan.Scan() {
		line := scan.Text()
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		var name, arch, version, sourcePackage, sourceVersion string
		if scheme == "debian" {
			if len(fields) != 4 && len(fields) != 6 {
				return nil, index, fmt.Errorf("malformed dpkg-query record")
			}
			if fields[3] != "install ok installed" && fields[3] != "hold ok installed" {
				continue
			}
			name, version, arch = fields[0], fields[1], fields[2]
			if len(fields) == 6 {
				sourcePackage, sourceVersion = fields[4], fields[5]
				if !packageText(sourcePackage) || sourceVersion == "" || len(sourceVersion) > 512 {
					return nil, index, fmt.Errorf("invalid source package metadata")
				}
			}
		} else {
			if len(fields) != 5 {
				return nil, index, fmt.Errorf("malformed rpm query record")
			}
			name, arch = fields[0], fields[4]
			var err error
			version, err = rpmEVR(fields[1], fields[2], fields[3])
			if err != nil {
				return nil, index, err
			}
		}
		if !packageText(name) || !packageText(arch) || version == "" || len(version) > 512 {
			return nil, index, fmt.Errorf("invalid installed package identity/version")
		}
		id := componentID(scheme, name, arch)
		if versions[id] == nil {
			versions[id] = map[string]bool{}
		}
		if versions[id][version] {
			return nil, index, fmt.Errorf("duplicate installed package instance")
		}
		if scheme == "debian" && len(versions[id]) > 0 {
			return nil, index, fmt.Errorf("multiple Debian versions for one installed package")
		}
		versions[id][version] = true
		index.ByID[id] = inventory.Component{ID: id, Kind: "package", Name: name, Architecture: arch, Source: map[string]string{"debian": "dpkg-query", "rpm": "rpm-query"}[scheme], SourcePackage: sourcePackage, SourceVersion: sourceVersion, VersionScheme: scheme, ProductKey: name + ":" + arch, State: "installed"}
	}
	if err := scan.Err(); err != nil {
		return nil, index, err
	}
	if len(index.ByID) == 0 {
		return nil, index, fmt.Errorf("installed package database returned no packages")
	}
	result := []inventory.Component{}
	for id, c := range index.ByID {
		installed := []string{}
		for v := range versions[id] {
			installed = append(installed, v)
		}
		sort.Strings(installed)
		if len(installed) == 1 {
			c.Version = installed[0]
		} else {
			c.InstalledVersions = installed
		}
		index.ByID[id] = c
		index.ByName[c.Name] = append(index.ByName[c.Name], id)
		result = append(result, c)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, index, nil
}
