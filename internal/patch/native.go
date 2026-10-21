// SPDX-License-Identifier: Apache-2.0
package patch

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	linuxcollector "github.com/rkislov/cerber/internal/collector/linux"
	"github.com/rkislov/cerber/internal/collector/windows"
	"github.com/rkislov/cerber/internal/inventory"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

//go:embed dnf.py
var dnfScript string

//go:embed install.ps1
var windowsScript string
var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+_.-]{0,255}$`)
var versionPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+:~_.-]{0,511}$`)

type Runner func(context.Context, string, ...string) ([]byte, error)
type Native struct {
	Run      Runner
	Collect  func(context.Context, string) (inventory.Snapshot, error)
	ReadFile func(string) ([]byte, error)
}

func runNative(ctx context.Context, name string, args ...string) ([]byte, error) {
	var nonce [8]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return nil, e
	}
	unit := "cerber-patch-" + hex.EncodeToString(nonce[:])
	sandbox := []string{"--quiet", "--pipe", "--wait", "--collect", "--unit=" + unit, "--property=SystemCallFilter=~@reboot", "--property=InaccessiblePaths=-/run/systemd/private -/run/dbus/system_bus_socket -/proc/sysrq-trigger", "--property=ProtectKernelTunables=yes", "--property=NoNewPrivileges=yes", "--property=RuntimeMaxSec=5400", "--setenv=LC_ALL=C", "--setenv=DEBIAN_FRONTEND=noninteractive", "--setenv=NEEDRESTART_MODE=l", "--", name}
	cmd := exec.CommandContext(ctx, "/usr/bin/systemd-run", append(sandbox, args...)...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l"}
	var out limitedOutput
	cmd.Stdout = &out
	var diagnostic limitedOutput
	cmd.Stderr = &diagnostic
	e := cmd.Run()
	return out.Bytes(), e
}

type limitedOutput struct{ bytes.Buffer }

func (b *limitedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 4<<20 {
		return 0, fmt.Errorf("native output exceeds limit")
	}
	return b.Buffer.Write(p)
}
func (n Native) Execute(ctx context.Context, q Request) Result {
	if q.Validate() != nil {
		return Failure(q, "invalid_request")
	}
	if q.Manager == "wua" {
		if runtime.GOOS != "windows" && n.Run == nil {
			return Failure(q, "unsupported_platform")
		}
		b, _ := json.Marshal(q)
		source := "$q = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + base64.StdEncoding.EncodeToString(b) + "')) | ConvertFrom-Json\n" + windowsScript
		var data []byte
		var e error
		if n.Run != nil {
			data, e = n.Run(ctx, "powershell", source)
		} else {
			data, e = windows.RunScript(ctx, source)
		}
		var r Result
		if e != nil || json.Unmarshal(bytes.TrimPrefix(data, []byte{239, 187, 191}), &r) != nil || r.Validate(q) != nil {
			return unknownResult(q, "windows_executor_failed_reconcile_history")
		}
		return r
	}
	if runtime.GOOS != "linux" && n.Run == nil {
		return Failure(q, "unsupported_platform")
	}
	run := n.Run
	if run == nil {
		run = runNative
	}
	collect := n.Collect
	if collect == nil {
		collect = func(ctx context.Context, manager string) (inventory.Snapshot, error) {
			return (linuxcollector.Collector{CheckAvailable: true, Manager: manager}).Collect(ctx)
		}
	}
	before, e := collect(ctx, q.Manager)
	if e != nil {
		return Failure(q, "applicability_collection_failed")
	}
	for _, u := range q.Updates {
		if !namePattern.MatchString(u.Title) || !namePattern.MatchString(u.Architecture) || !versionPattern.MatchString(u.AvailableVersion) {
			return Failure(q, "invalid_package_identity")
		}
		found := false
		for _, v := range before.Updates {
			found = found || Matches(u, v)
		}
		if !found {
			return Failure(q, "candidate_changed_refresh_inventory")
		}
	}
	if q.Manager == "dnf" {
		b, _ := json.Marshal(q)
		source := "import json,base64\nq=json.loads(base64.b64decode('" + base64.StdEncoding.EncodeToString(b) + "'))\n" + dnfScript
		data, e := run(ctx, "/usr/bin/python3", "-c", source)
		var r Result
		if e != nil || json.Unmarshal(data, &r) != nil || r.Validate(q) != nil {
			return unknownResult(q, "dnf_executor_failed_reconcile_history")
		}
		if q.Mode == "install" {
			r.Reboot = n.linuxReboot(q, r)
		}
		return r
	}
	if q.Manager != "apt" {
		return Failure(q, "unsupported_package_manager")
	}
	args := []string{"-o", "APT::Get::AllowUnauthenticated=false", "-o", "Acquire::AllowInsecureRepositories=false", "--no-remove", "--only-upgrade", "--no-install-recommends", "-o", "Dpkg::Options::=--force-confold", "install"}
	for _, u := range q.Updates {
		args = append(args, u.Title+":"+u.Architecture+"="+u.AvailableVersion)
	}
	simulation, e := run(ctx, "/usr/bin/apt-get", append([]string{"--simulate"}, args...)...)
	if e != nil {
		return Failure(q, "apt_simulation_failed")
	}
	if !aptPlanAllowed(string(simulation), q) {
		return Failure(q, "transaction_requires_unselected_packages")
	}
	r := Result{ID: q.ID, Status: "succeeded", Reboot: "unknown", Items: []Item{}}
	if q.Mode == "preview" {
		for _, u := range q.Updates {
			r.Items = append(r.Items, Item{u.ID, "ready", "applicable"})
		}
		r.Detail = "Exact package versions; dependency additions/removals rejected"
		return r
	}
	cache, e := os.MkdirTemp("", "cerber-patch-")
	if e != nil {
		return Failure(q, "private_download_directory_failed")
	}
	defer os.RemoveAll(cache)
	_, e = run(ctx, "/usr/bin/apt-get", append([]string{"--download-only", "--assume-yes", "-o", "Dir::Cache::archives=" + cache}, args...)...)
	if e != nil {
		return Failure(q, "apt_download_failed")
	}
	files, e := os.ReadDir(cache)
	if e != nil {
		return Failure(q, "apt_download_unavailable")
	}
	archives := map[string]string{}
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".deb") {
			continue
		}
		path := filepath.Join(cache, file.Name())
		data, e := run(ctx, "/usr/bin/dpkg-deb", "--show", "--showformat=${Package}\t${Version}\t${Architecture}\n", path)
		if e != nil {
			return Failure(q, "download_metadata_failed")
		}
		fields := strings.Fields(string(data))
		if len(fields) != 3 {
			return Failure(q, "download_metadata_invalid")
		}
		for _, u := range q.Updates {
			if fields[0] == u.Title && fields[1] == u.AvailableVersion && fields[2] == u.Architecture {
				if archives[u.ID] != "" {
					return Failure(q, "duplicate_download")
				}
				archives[u.ID] = path
			}
		}
	}
	dpkgArgs := []string{"--force-confold", "--install"}
	for _, u := range q.Updates {
		if archives[u.ID] == "" {
			return Failure(q, "selected_download_missing")
		}
		dpkgArgs = append(dpkgArgs, archives[u.ID])
	}
	if !time.Now().Before(q.ExpiresAt) {
		return Failure(q, "authorization_expired_before_install")
	}
	_, installErr := run(ctx, "/usr/bin/dpkg", dpkgArgs...)
	after, e := collect(ctx, q.Manager)
	if e != nil {
		return unknownResult(q, "post_install_inventory_failed")
	}
	good := 0
	for _, u := range q.Updates {
		item := Item{u.ID, "failed", "target_version_not_observed"}
		for _, c := range after.Components {
			if c.ID == u.ID && c.Version == u.AvailableVersion && c.State != "broken" {
				item.Status = "installed"
				item.Code = "target_version_observed"
				good++
				break
			}
		}
		r.Items = append(r.Items, item)
	}
	if good == 0 {
		r.Status = "failed"
	} else if good < len(q.Updates) {
		r.Status = "partial"
	}
	if installErr != nil {
		r.Detail = "Package manager returned an error; results reflect observed versions, verify package health"
		if good == len(q.Updates) {
			r.Status = "unknown"
			for i := range r.Items {
				r.Items[i].Status = "unknown"
			}
		}
	}
	r.Reboot = n.linuxReboot(q, r)
	return r
}
func unknownResult(q Request, code string) Result {
	r := Failure(q, code)
	r.Status = "unknown"
	for i := range r.Items {
		r.Items[i].Status = "unknown"
	}
	return r
}
func aptPlanAllowed(data string, q Request) bool {
	inst := 0
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if f[0] == "Remv" {
			return false
		}
		if f[0] != "Inst" {
			continue
		}
		if len(f) < 4 {
			return false
		}
		inst++
		matched := false
		for _, u := range q.Updates {
			if (f[1] == u.Title || f[1] == u.Title+":"+u.Architecture) && strings.Contains(line, "("+u.AvailableVersion+" ") {
				matched = true
			}
		}
		if !matched {
			return false
		}
	}
	return inst == len(q.Updates)
}

func (n Native) linuxReboot(q Request, r Result) string {
	read := n.ReadFile
	if read == nil {
		read = os.ReadFile
	}
	if _, e := read("/var/run/reboot-required"); e == nil {
		return "yes"
	}
	for _, u := range q.Updates {
		observed := false
		for _, i := range r.Items {
			if i.ID == u.ID && (i.Status == "installed" || i.Status == "already_installed") {
				observed = true
			}
		}
		if !observed {
			continue
		}
		if u.Title == "kernel" || u.Title == "kernel-core" || u.Title == "kernel-default" || strings.HasPrefix(u.Title, "linux-image-") {
			return "yes"
		}
	}
	return "unknown"
}
