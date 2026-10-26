// SPDX-License-Identifier: Apache-2.0
package linux

import (
	"context"
	"fmt"
	"github.com/rkislov/cerber/internal/inventory"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type Collector struct {
	CheckAvailable  bool
	RefreshMetadata bool
	Manager         string // auto, apt (dpkg), apt-rpm, dnf, yum
	Timeout         time.Duration
	Runner          Runner
	Lookup          func(string) (string, error)
	ReadFile        func(string) ([]byte, error)
}

func (c Collector) Collect(ctx context.Context) (inventory.Snapshot, error) {
	s := inventory.Snapshot{SchemaVersion: 1, ID: "pending", AssetID: "pending", Collector: "cerber-linux/1", Components: []inventory.Component{}, Updates: []inventory.Update{}, Coverage: []inventory.Coverage{}, OS: inventory.OS{Family: "linux"}}
	if c.Runner == nil && runtime.GOOS != "linux" {
		return s, fmt.Errorf("local Linux collector requires Linux")
	}
	if c.RefreshMetadata && !c.CheckAvailable {
		return s, fmt.Errorf("metadata refresh requires package update checking")
	}
	runner := c.Runner
	if runner == nil {
		runner = run
	}
	lookup := c.Lookup
	if lookup == nil {
		lookup = exec.LookPath
	}
	read := c.ReadFile
	if read == nil {
		read = os.ReadFile
	}
	limit := c.Timeout
	if limit <= 0 {
		limit = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	coverage := func(section, status, detail string) {
		if len(detail) > 4096 {
			detail = detail[:4096]
		}
		s.Coverage = append(s.Coverage, inventory.Coverage{Section: section, Status: status, Detail: detail})
	}
	data, err := read("/etc/os-release")
	if err != nil {
		data, err = read("/usr/lib/os-release")
	}
	values := map[string]string{}
	osStatus := "complete"
	osDetail := "os-release and uname; no shell evaluation"
	if err == nil {
		values, err = OSRelease(data)
	}
	if err != nil {
		osStatus = "partial"
		osDetail = "os-release unavailable or unrecognized"
		values = map[string]string{}
	}
	s.OS.Name = values["PRETTY_NAME"]
	if s.OS.Name == "" {
		s.OS.Name = values["NAME"]
	}
	if s.OS.Name == "" {
		s.OS.Name = "Linux"
	}
	s.OS.DistributionID = values["ID"]
	s.OS.CPEName = values["CPE_NAME"]
	s.OS.BranchID = values["ALT_BRANCH_ID"]
	s.OS.IDLike = strings.Fields(values["ID_LIKE"])
	s.OS.Codename = values["VERSION_CODENAME"]
	s.OS.Version = values["VERSION_ID"]
	if s.OS.Version == "" {
		s.OS.Version = values["VERSION"]
	}
	s.OS.Build = values["BUILD_ID"]
	arch, archErr := runner(ctx, "uname", "-m")
	kernel, kernelErr := runner(ctx, "uname", "-r")
	if archErr == nil && arch.ExitCode == 0 {
		s.OS.Architecture = strings.TrimSpace(arch.Stdout)
	}
	if kernelErr == nil && kernel.ExitCode == 0 {
		s.OS.Kernel = strings.TrimSpace(kernel.Stdout)
	}
	if s.OS.Version == "" || s.OS.Architecture == "" || s.OS.Kernel == "" {
		osStatus = "partial"
	}
	coverage("os", osStatus, osDetail)
	coverage("applications", "unsupported", "Package inventory does not cover portable applications, containers, language-specific registries or Flatpak/Snap")
	coverage("components", "unsupported", "OS components represented as native packages where applicable")
	coverage("updates_installed", "unsupported", "Installed package EVRs are recorded; package transaction history is not collected")
	manager, err := selectManager(c.Manager, values, lookup)
	if err != nil {
		coverage("packages", "error", err.Error())
		coverage("updates_available", "error", err.Error())
		if ctx.Err() != nil {
			return s, ctx.Err()
		}
		s.CollectedAt = time.Now().UTC()
		return s, s.Validate()
	}
	s.PackageManager = manager
	scheme, command, args := "rpm", "rpm", []string{"-qa", "--qf", rpmFormat}
	if manager == "apt" {
		scheme, command, args = "debian", "dpkg-query", []string{"-W", "-f", dpkgFormat}
	}
	r, err := runner(ctx, command, args...)
	if err == nil && r.ExitCode != 0 {
		err = commandFailure(command, r)
	}
	var index packageIndex
	if err == nil {
		s.Components, index, err = parsePackages(r.Stdout, scheme)
	}
	if err != nil {
		coverage("packages", "error", err.Error())
		coverage("updates_available", "error", "Installed package inventory failed; no candidate matching performed")
	} else {
		coverage("packages", "complete", "Native installed-package database; RPM parallel installed EVRs are preserved as a set")
		if !c.CheckAvailable {
			coverage("updates_available", "not_requested", "Use -check-package-updates; repository metadata is not refreshed automatically")
		} else {
			s.RepositoryMetadata = "cache"
			source := manager + "-cache"
			if c.RefreshMetadata {
				s.RepositoryMetadata = "refreshed"
				source = manager + "-refreshed"
				if manager == "yum" {
					refresh, e := runner(ctx, "yum", "-q", "--setopt=*.skip_if_unavailable=False", "makecache")
					if e != nil {
						err = e
					} else if refresh.ExitCode != 0 {
						err = commandFailure("yum metadata refresh", refresh)
					}
				}
				if manager == "apt" || manager == "apt-rpm" {
					refresh, e := runner(ctx, "apt-get", "-o", "APT::Update::Error-Mode=any", "update")
					if e != nil {
						err = e
					} else if refresh.ExitCode != 0 || strings.TrimSpace(refresh.Stderr) != "" {
						err = fmt.Errorf("APT metadata refresh failed or reported warnings; inspect repository configuration locally")
					}
				}
			}
			if err == nil {
				var result Result
				if manager == "apt" || manager == "apt-rpm" {
					result, err = runner(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade")
					if err == nil && result.ExitCode != 0 {
						err = commandFailure("apt-get simulation", result)
					}
					if err == nil {
						s.Updates, err = parseAPT(result.Stdout, source, index)
					}
				} else {
					opts := []string{"-q", "-C", "check-update"}
					if c.RefreshMetadata && manager == "dnf" {
						opts = []string{"-q", "--refresh", "--setopt=*.skip_if_unavailable=False", "check-update"}
					}
					result, err = runner(ctx, manager, opts...)
					if err == nil && result.ExitCode != 0 && result.ExitCode != 100 {
						err = commandFailure(manager+" check-update", result)
					}
					if err == nil {
						s.Updates, err = parseRPMUpdates(result.Stdout, source, index)
					}
					if err == nil && result.ExitCode == 100 && len(s.Updates) == 0 {
						err = fmt.Errorf("RPM frontend reported updates but no installed-package candidates were recognized")
					}
				}
			}
			if err != nil {
				s.Updates = []inventory.Update{}
				if c.RefreshMetadata {
					s.RepositoryMetadata = "refresh_failed"
				}
				coverage("updates_available", "error", err.Error())
			} else {
				coverage("updates_available", "partial", "Native package-manager candidates only; dependencies, removals, obsoletes and full deployment applicability are not modelled. Metadata mode: "+s.RepositoryMetadata+"; cache freshness is not independently verified")
			}
		}
	}
	if ctx.Err() != nil {
		return s, ctx.Err()
	}
	s.CollectedAt = time.Now().UTC()
	return s, s.Validate()
}
func selectManager(request string, values map[string]string, lookup func(string) (string, error)) (string, error) {
	available := func(name string) bool { _, err := lookup(name); return err == nil }
	if request == "" {
		request = "auto"
	}
	if request != "auto" {
		switch request {
		case "apt":
			if available("dpkg-query") && available("apt-get") {
				return request, nil
			}
		case "apt-rpm":
			if available("rpm") && available("apt-get") {
				return request, nil
			}
		case "dnf", "yum":
			if available("rpm") && available(request) {
				return request, nil
			}
		default:
			return "", fmt.Errorf("unknown package manager")
		}
		return "", fmt.Errorf("requested package manager tools are unavailable")
	}
	if hasFamily(values, "altlinux", "alt") {
		if available("rpm") && available("apt-get") {
			return "apt-rpm", nil
		}
		return "", fmt.Errorf("ALT requires rpm and apt-get (APT-RPM)")
	}
	if hasFamily(values, "debian", "ubuntu", "astra", "astralinux", "astra_linux") {
		if available("dpkg-query") && available("apt-get") {
			return "apt", nil
		}
		return "", fmt.Errorf("Debian/Astra package manager tools unavailable")
	}
	if available("rpm") {
		if available("dnf") {
			return "dnf", nil
		}
		if available("yum") {
			return "yum", nil
		}
	}
	if available("dpkg-query") && available("apt-get") {
		return "apt", nil
	}
	return "", fmt.Errorf("supported package manager not found (APT/dpkg, APT-RPM, DNF or YUM)")
}
