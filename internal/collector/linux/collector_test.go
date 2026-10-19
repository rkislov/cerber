// SPDX-License-Identifier: Apache-2.0
package linux

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestNativeCandidates(t *testing.T) {
	for _, tc := range []struct {
		id, manager, packages, output, want string
		exit                                int
	}{
		{"astra", "apt", "libc6\t2:2.31-1+astra1\tamd64\tinstall ok installed\nold\t1\tamd64\tdeinstall ok config-files\n", "1 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\nInst libc6 [2:2.31-1+astra1] (2:2.31-1+astra2 Astra [amd64])\nInst dep (1 Astra [amd64])\n", "2:2.31-1+astra2", 0},
		{"redos", "dnf", "kernel\t(none)\t6.1\t1.red\tx86_64\nkernel\t(none)\t6.1\t2.red\tx86_64\n", "kernel.x86_64 6.1-3.red updates\n", "0:6.1-3.red", 100},
		{"altlinux", "apt-rpm", "bash\t1\t5.2\talt1\taarch64\n", "1 upgraded, 0 newly installed, 0 removed and 0 not upgraded.\nInst bash [1:5.2-alt1] (1:5.2-alt2 ALT [aarch64])\n", "1:5.2-alt2", 0},
	} {
		t.Run(tc.id, func(t *testing.T) {
			var calls []string
			c := Collector{CheckAvailable: true, ReadFile: func(string) ([]byte, error) { return []byte("ID=" + tc.id + "\nNAME=Test\nVERSION_ID=1\n"), nil }, Lookup: func(name string) (string, error) {
				if name == "apt-get" && tc.manager == "dnf" {
					return "", fmt.Errorf("missing")
				}
				return name, nil
			}, Runner: func(ctx context.Context, name string, args ...string) (Result, error) {
				calls = append(calls, name+" "+strings.Join(args, " "))
				switch name {
				case "uname":
					return Result{Stdout: "x86_64"}, nil
				case "rpm", "dpkg-query":
					return Result{Stdout: tc.packages}, nil
				default:
					return Result{Stdout: tc.output, ExitCode: tc.exit}, nil
				}
			}}
			s, err := c.Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if s.PackageManager != tc.manager || s.CoverageStatus("updates_available") != "partial" || len(s.Updates) != 1 {
				t.Fatalf("unexpected snapshot: %+v calls=%v", s, calls)
			}
			if s.Updates[0].AvailableVersion != tc.want {
				t.Fatal(s.Updates)
			}
			if tc.id == "redos" && len(s.Components[0].InstalledVersions) != 2 {
				t.Fatal("lost parallel kernels")
			}
			for _, call := range calls {
				if strings.Contains(call, " update") || strings.Contains(call, " install") || strings.Contains(call, "--refresh") {
					t.Fatalf("unexpected mutation/network: %s", call)
				}
			}
		})
	}
}
func TestAPTRejectsAmbiguousArchitecture(t *testing.T) {
	_, index, err := parsePackages("p\t1\tamd64\tinstall ok installed\np\t1\ti386\tinstall ok installed\n", "debian")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = parseAPT("1 upgraded,\nInst p [1] (2 repo)\n", "apt-cache", index); err == nil {
		t.Fatal("accepted ambiguous multiarch candidate")
	}
}
func TestRefreshFailureAndExitCodes(t *testing.T) {
	for _, code := range []int{0, 1, 100} {
		c := Collector{Manager: "dnf", CheckAvailable: true, Lookup: func(s string) (string, error) { return s, nil }, ReadFile: func(string) ([]byte, error) { return []byte("ID=redos\nVERSION_ID=8\nNAME=RED\n"), nil }, Runner: func(ctx context.Context, n string, a ...string) (Result, error) {
			switch n {
			case "uname":
				return Result{Stdout: "x86_64"}, nil
			case "rpm":
				return Result{Stdout: "p\t0\t1\t1\tx86_64\n"}, nil
			}
			return Result{ExitCode: code}, nil
		}}
		s, err := c.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		want := "error"
		if code == 0 {
			want = "partial"
		}
		if s.CoverageStatus("updates_available") != want {
			t.Fatalf("code %d: %+v", code, s)
		}
	}
	c := Collector{Manager: "apt", CheckAvailable: true, RefreshMetadata: true, Lookup: func(s string) (string, error) { return s, nil }, ReadFile: func(string) ([]byte, error) { return []byte("ID=astra\nVERSION_ID=1\nNAME=Astra\n"), nil }, Runner: func(ctx context.Context, n string, a ...string) (Result, error) {
		switch n {
		case "uname":
			return Result{Stdout: "aarch64"}, nil
		case "dpkg-query":
			return Result{Stdout: "p\t1\tarm64\tinstall ok installed\n"}, nil
		}
		if a[len(a)-1] != "update" {
			t.Fatal("queried after failed refresh")
		}
		return Result{Stderr: "W: repository unavailable"}, nil
	}}
	s, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.RepositoryMetadata != "refresh_failed" || s.CoverageStatus("updates_available") != "error" {
		t.Fatal(s)
	}
}
func TestOSReleaseDoesNotExecute(t *testing.T) {
	v, err := OSRelease([]byte("ID=astra\nPRETTY_NAME=\"Astra $(touch /tmp/nope)\"\n"))
	if err != nil || !strings.Contains(v["PRETTY_NAME"], "$(touch") {
		t.Fatal(v, err)
	}
}

func TestNativeLinuxInventory(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("CERBER_NATIVE_SMOKE") != "1" {
		t.Skip("native Linux smoke")
	}
	s, err := (Collector{CheckAvailable: true}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.CoverageStatus("packages") != "complete" || len(s.Components) == 0 {
		t.Fatalf("native package inventory failed: %+v", s.Coverage)
	}
	if s.CoverageStatus("updates_available") != "partial" {
		t.Fatalf("native cached update query failed: %+v", s.Coverage)
	}
}
