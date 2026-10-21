// SPDX-License-Identifier: Apache-2.0
package patch

import (
	"context"
	"fmt"
	"github.com/rkislov/cerber/internal/inventory"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This native test builds inert packages and installs exclusively into a temporary dpkg root.
// No host package database, services or repository configuration is touched.
func TestNativeDpkgIsolatedRoot(t *testing.T) {
	if _, e := exec.LookPath("dpkg-deb"); e != nil {
		t.Skip("dpkg-deb unavailable")
	}
	ctx := context.Background()
	root := t.TempDir()
	pkg := filepath.Join(root, "build")
	if e := os.MkdirAll(filepath.Join(pkg, "DEBIAN"), 0755); e != nil {
		t.Fatal(e)
	}
	control := "Package: cerber-patch-fixture\nVersion: 1.1\nArchitecture: all\nMaintainer: Cerber fixture <fixture@example.invalid>\nDescription: Inert managed update test\n"
	if e := os.WriteFile(filepath.Join(pkg, "DEBIAN", "control"), []byte(control), 0644); e != nil {
		t.Fatal(e)
	}
	deb := filepath.Join(root, "fixture.deb")
	if out, e := exec.Command("dpkg-deb", "--build", pkg, deb).CombinedOutput(); e != nil {
		t.Fatal(string(out), e)
	}
	installRoot := filepath.Join(root, "installed")
	adminDir := filepath.Join(installRoot, "var/lib/dpkg")
	if e := os.MkdirAll(adminDir, 0700); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(adminDir, "status"), nil, 0600)
	q := request()
	q.Mode = "install"
	q.Updates[0].ID = "debian:cerber-patch-fixture:all"
	q.Updates[0].Title = "cerber-patch-fixture"
	q.Updates[0].Architecture = "all"
	calls := 0
	n := Native{Collect: func(context.Context, string) (inventory.Snapshot, error) {
		calls++
		if calls == 1 {
			return inventory.Snapshot{Updates: q.Updates}, nil
		}
		out, e := exec.Command("dpkg-query", "--admindir="+adminDir, "-W", "-f=${Version}", "cerber-patch-fixture").Output()
		if e != nil {
			return inventory.Snapshot{}, e
		}
		return inventory.Snapshot{Components: []inventory.Component{{ID: q.Updates[0].ID, Version: strings.TrimSpace(string(out))}}}, nil
	}, Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "/usr/bin/apt-get" {
			if args[0] == "--simulate" {
				return []byte("Inst cerber-patch-fixture [1.0] (1.1 stable [all])"), nil
			}
			for _, arg := range args {
				if strings.HasPrefix(arg, "Dir::Cache::archives=") {
					cache := strings.TrimPrefix(arg, "Dir::Cache::archives=")
					b, _ := os.ReadFile(deb)
					return nil, os.WriteFile(filepath.Join(cache, "fixture.deb"), b, 0600)
				}
			}
			return nil, fmt.Errorf("missing private download cache")
		}
		if name == "/usr/bin/dpkg" {
			args = append([]string{"--force-not-root", "--root=" + installRoot, "--admindir=" + adminDir}, args...)
		}
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}}
	r := n.Execute(ctx, q)
	if r.Status != "succeeded" || r.Items[0].Status != "installed" {
		t.Fatal(r)
	}
}
