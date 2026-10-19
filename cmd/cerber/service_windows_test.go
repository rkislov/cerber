// SPDX-License-Identifier: Apache-2.0
//go:build windows

package main

import (
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsServiceLifecycle(t *testing.T) {
	if os.Getenv("CERBER_SERVICE_SMOKE") != "1" {
		t.Skip("explicit elevated CI smoke only")
	}
	binary, err := filepath.Abs(os.Getenv("CERBER_SERVICE_BINARY"))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(os.Getenv("ProgramData"), "Cerber")
	program := filepath.Join(os.Getenv("ProgramFiles"), "Cerber")
	for _, path := range []string{root, program} {
		if _, err = os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("managed path already exists: %s", path)
		}
	}
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()
	if existing, e := manager.OpenService(serviceName); e == nil {
		existing.Close()
		t.Fatal("service already exists; disposable runner required")
	}
	defer func() {
		if s, e := manager.OpenService(serviceName); e == nil {
			s.Control(svc.Stop)
			for i := 0; i < 400; i++ {
				v, e := s.Query()
				if e != nil || v.State == svc.Stopped {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			s.Delete()
			s.Close()
		}
		os.RemoveAll(root)
		os.RemoveAll(program)
	}()
	control := func(command string) {
		t.Helper()
		s, err := manager.OpenService(serviceName)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		want := svc.Running
		if command == "start" {
			err = s.Start()
		} else {
			want = svc.Stopped
			_, err = s.Control(svc.Stop)
		}
		if err != nil {
			t.Fatal(command, err)
		}
		waitFor(t, 40*time.Second, func() bool { v, e := s.Query(); return e == nil && v.State == want }, "SCM did not reach "+command)
	}
	serviceFixture(t, root, filepath.Join(root, "config"), filepath.Join(root, "state"), func() {
		script, err := filepath.Abs("../../deploy/windows/Install-CerberAgent.ps1")
		if err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, "-Binary", binary).CombinedOutput()
		if err != nil {
			t.Fatal(string(out), err)
		}
	}, func() { control("start") }, func() { control("stop") })
}
