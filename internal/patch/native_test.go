// SPDX-License-Identifier: Apache-2.0
package patch

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/inventory"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func request() Request {
	return Request{SchemaVersion: 1, ID: strings.Repeat("a", 32), AgentID: "agent-1", InventoryID: "snapshot", Mode: "preview", Manager: "apt", NoReboot: true, ExpiresAt: time.Now().Add(time.Hour), Updates: []inventory.Update{{ID: "debian:openssl:amd64", Title: "openssl", State: "available", Source: "apt-cache", InstalledVersion: "1.0", AvailableVersion: "1.1", Architecture: "amd64", Repository: "stable [amd64]", VersionScheme: "debian", KBs: []string{}}}}
}
func TestSignedAuthorization(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	q := request()
	ticket, e := Sign(q, key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ticket.Verify(pub, q.AgentID, time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e = ticket.Verify(pub, "other", time.Now()); e == nil {
		t.Fatal("wrong agent")
	}
	if _, e = ticket.Verify(pub, q.AgentID, q.ExpiresAt); e == nil {
		t.Fatal("expired authorization")
	}
	ticket.Payload[0] ^= 1
	if _, e = ticket.Verify(pub, q.AgentID, time.Now()); e == nil {
		t.Fatal("tampered")
	}
	q.NoReboot = false
	if _, e = Sign(q, key); e == nil {
		t.Fatal("reboot enabled")
	}
	q = request()
	q.ID = "../../" + strings.Repeat("a", 26)
	if q.Validate() == nil {
		t.Fatal("unsafe spool ID")
	}
}
func TestAPTPreviewRejectsUnselectedTransaction(t *testing.T) {
	q := request()
	for _, plan := range []string{"Inst openssl [1.0] (1.1 stable [amd64])\nInst extra [1] (2 stable [amd64])", "Remv old\nInst openssl [1.0] (1.1 stable [amd64])", "Inst openssl [1.0] (1.2 stable [amd64])"} {
		if aptPlanAllowed(plan, q) {
			t.Fatal(plan)
		}
	}
	calls := 0
	n := Native{Collect: func(context.Context, string) (inventory.Snapshot, error) {
		return inventory.Snapshot{Updates: q.Updates}, nil
	}, Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls++
		if name != "/usr/bin/apt-get" || args[0] != "--simulate" {
			t.Fatal("mutating preview", name, args)
		}
		return []byte("Inst openssl [1.0] (1.1 stable [amd64])"), nil
	}}
	r := n.Execute(context.Background(), q)
	if r.Status != "succeeded" || r.Items[0].Status != "ready" || r.Validate(q) != nil || calls != 1 {
		t.Fatal(r, calls)
	}
	q.Updates[0].Title = "--allow-unauthenticated"
	calls = 0
	r = n.Execute(context.Background(), q)
	if r.Status != "failed" || calls != 0 {
		t.Fatal("injected option", r, calls)
	}
}
func TestAPTInstallExactArchivesAndReboot(t *testing.T) {
	q := request()
	q.Mode = "install"
	collections := 0
	installed := false
	n := Native{Collect: func(context.Context, string) (inventory.Snapshot, error) {
		collections++
		if collections == 1 {
			return inventory.Snapshot{Updates: q.Updates}, nil
		}
		return inventory.Snapshot{Components: []inventory.Component{{ID: q.Updates[0].ID, Version: "1.1"}}}, nil
	}, ReadFile: func(string) ([]byte, error) { return []byte(""), nil }, Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "/usr/bin/apt-get":
			if args[0] == "--simulate" {
				return []byte("Inst openssl [1.0] (1.1 stable [amd64])"), nil
			}
			if args[0] != "--download-only" {
				t.Fatal("unexpected apt apply", args)
			}
			for _, a := range args {
				if strings.HasPrefix(a, "Dir::Cache::archives=") {
					p := strings.TrimPrefix(a, "Dir::Cache::archives=")
					if e := os.WriteFile(filepath.Join(p, "fixture.deb"), nil, 0600); e != nil {
						t.Fatal(e)
					}
				}
			}
			return nil, nil
		case "/usr/bin/dpkg-deb":
			return []byte("openssl\t1.1\tamd64\n"), nil
		case "/usr/bin/dpkg":
			installed = true
			if len(args) != 3 || args[0] != "--force-confold" || !strings.HasSuffix(args[2], "fixture.deb") {
				t.Fatal(args)
			}
			return nil, nil
		default:
			t.Fatal(name)
			return nil, errors.New("bad command")
		}
	}}
	r := n.Execute(context.Background(), q)
	if !installed || r.Status != "succeeded" || r.Reboot != "yes" || r.Items[0].Status != "installed" || r.Validate(q) != nil {
		t.Fatal(r, installed)
	}
}
func TestWindowsResultAndNoRebootContract(t *testing.T) {
	q := request()
	q.Manager = "wua"
	q.Mode = "install"
	expected := Result{ID: q.ID, Status: "partial", Reboot: "yes", Items: []Item{{q.Updates[0].ID, "installed", "wua_result_2"}}}
	expected.Status = "succeeded"
	n := Native{Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		source := args[0]
		if !strings.Contains(source, "ForceQuiet=$true") || strings.Contains(source, "Restart-Computer") || strings.Contains(source, ".AcceptEula(") {
			t.Fatal("unsafe Windows script")
		}
		return json.Marshal(expected)
	}}
	r := n.Execute(context.Background(), q)
	if r.Reboot != "yes" || r.Status != "succeeded" {
		t.Fatal(r)
	}
	expected.Items = append(expected.Items, expected.Items[0])
	r = n.Execute(context.Background(), q)
	if r.Status != "unknown" {
		t.Fatal("malformed executor success", r)
	}
}
func TestResultCannotHidePartialFailure(t *testing.T) {
	q := request()
	q.Mode = "install"
	u := q.Updates[0]
	u.ID = "second"
	q.Updates = append(q.Updates, u)
	r := Result{ID: q.ID, Status: "succeeded", Reboot: "unknown", Items: []Item{{q.Updates[0].ID, "installed", "ok"}, {u.ID, "failed", "error"}}}
	if r.Validate(q) == nil {
		t.Fatal("false success")
	}
	r.Status = "partial"
	if r.Validate(q) != nil {
		t.Fatal("valid partial")
	}
}
