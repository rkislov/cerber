// SPDX-License-Identifier: Apache-2.0
//go:build linux

package main

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

func TestSystemdServiceLifecycle(t *testing.T) {
	if os.Getenv("CERBER_SERVICE_SMOKE") != "1" {
		t.Skip("explicit root CI smoke only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	binary := os.Getenv("CERBER_SERVICE_BINARY")
	const unit = "/etc/systemd/system/cerber-agent.service"
	paths := []string{"/etc/cerber", "/var/lib/cerber", "/opt/cerber", unit}
	for _, p := range paths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("managed path already exists: %s", p)
		}
	}
	command := func(name string, args ...string) {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatal(name, args, string(out), err)
		}
	}
	created := false
	defer func() {
		exec.Command("systemctl", "stop", "cerber-agent").Run()
		for _, p := range paths {
			os.RemoveAll(p)
		}
		exec.Command("systemctl", "daemon-reload").Run()
		exec.Command("systemctl", "reset-failed", "cerber-agent").Run()
		if created {
			exec.Command("userdel", "cerber").Run()
		}
	}()
	if _, err := user.Lookup("cerber"); err == nil {
		t.Fatal("test account already exists")
	}
	command("useradd", "--system", "--user-group", "--home-dir", "/var/lib/cerber", "--no-create-home", "--shell", "/usr/sbin/nologin", "cerber")
	created = true
	account, err := user.Lookup("cerber")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	serviceFixture(t, "/etc/cerber", "/etc/cerber", "/var/lib/cerber", func() {
		command("install", "-d", "-m", "0755", "/opt/cerber")
		command("install", "-m", "0755", binary, "/opt/cerber/cerber")
		command("install", "-m", "0644", "../../deploy/linux/cerber-agent.service", unit)
		for _, root := range []string{"/etc/cerber", "/var/lib/cerber"} {
			err = filepath.Walk(root, func(path string, info os.FileInfo, e error) error {
				if e != nil {
					return e
				}
				owner := 0
				mode := os.FileMode(0640)
				if root == "/var/lib/cerber" {
					owner = uid
					mode = 0600
				}
				if info.IsDir() {
					mode |= 0110
				}
				if e = os.Chown(path, owner, gid); e != nil {
					return e
				}
				return os.Chmod(path, mode)
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		command("systemd-analyze", "verify", unit)
		command("systemctl", "daemon-reload")
	}, func() {
		command("systemctl", "start", "cerber-agent")
		command("systemctl", "is-active", "--quiet", "cerber-agent")
	}, func() { command("systemctl", "stop", "cerber-agent") })
}
