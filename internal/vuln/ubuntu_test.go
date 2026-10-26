// SPDX-License-Identifier: Apache-2.0
package vuln

import (
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/inventory"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestDebianDistributionVersionOrdering(t *testing.T) {
	pairs := [][3]string{{"1:9.6p1-3ubuntu13.20", "1:9.6p1-3ubuntu13.3", "gt"}, {"9.6p1-3ubuntu13.20", "1:9.6p1-3ubuntu13.3", "lt"}, {"1.0~rc1", "1.0", "lt"}, {"1.0", "1.0-0", "eq"}, {"01:1.0-01", "1:1.0-1", "eq"}, {"1.0+git", "1.0a", "gt"}, {"2.0-1+b1", "2.0-1", "gt"}, {"1.0002", "1.2", "eq"}, {"1.0~~", "1.0~", "lt"}, {"1.0-1~bpo12+1", "1.0-1", "lt"}}
	for _, p := range pairs {
		t.Run(p[0]+"/"+p[1], func(t *testing.T) {
			got, e := CompareDebian(p[0], p[1])
			if e != nil || p[2] == "lt" && got >= 0 || p[2] == "gt" && got <= 0 || p[2] == "eq" && got != 0 {
				t.Fatalf("%v %v", got, e)
			}
			if path, e := exec.LookPath("dpkg"); e == nil {
				if e = exec.Command(path, "--compare-versions", p[0], p[2], p[1]).Run(); e != nil {
					t.Fatal("dpkg disagrees", e)
				}
			}
		})
	}
	for _, v := range []string{"", "x1", "1:", "a:1.0", "1.0-", "1.0-1;sh", "1.0\n", "1.0/2"} {
		if _, e := CompareDebian(v, "1"); e == nil {
			t.Fatal("accepted", v)
		}
	}
}

const ubuntuFixture = `{"schema_version":"1.7.0","id":"UBUNTU-CVE-2024-6387","modified":"2025-09-08T00:00:00Z","affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"openssh"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:9.6p1-3ubuntu13.3"}]}],"ecosystem_specific":{"binaries":[{"binary_name":"openssh-server","binary_version":"1:9.6p1-3ubuntu13.3"},{"binary_name":"openssh-client","binary_version":"1:9.6p1-3ubuntu13.3"}]}}]}`

func TestUbuntuPackageEvidenceAndConservativeBoundaries(t *testing.T) {
	c := fixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	record, e := parseUbuntu([]byte(ubuntuFixture), "CVE-2024-6387")
	if e != nil {
		t.Fatal(e)
	}
	cache := UbuntuCache{Record: record, At: now, URL: ubuntuURL("CVE-2024-6387"), SHA256: "fixture"}
	put := func() {
		p, _ := json.Marshal(cache)
		if _, e := c.db.Exec("INSERT OR REPLACE INTO ubuntu_osv VALUES(?,?)", "CVE-2024-6387", string(p)); e != nil {
			t.Fatal(e)
		}
	}
	put()
	b := InventoryBinding{Link: InventoryLink{State: "linked", AgentID: "owner", SnapshotID: "inventory", CollectedAt: now}, Snapshot: inventory.Snapshot{CollectedAt: now, PackageManager: "apt", OS: inventory.OS{DistributionID: "ubuntu", Version: "24.04"}, Coverage: []inventory.Coverage{{Section: "packages", Status: "complete"}}, Components: []inventory.Component{{Name: "openssh-server", Version: "1:9.6p1-3ubuntu13.20", SourcePackage: "openssh", SourceVersion: "1:9.6p1-3ubuntu13.20", Source: "dpkg-query", VersionScheme: "debian", Kind: "package", State: "installed", Architecture: "amd64"}}}}
	m := Match{Record: Record{ID: "CVE-2024-6387"}, CPE: CPE("cpe:/a:openbsd:openssh:9.6p1")}
	check := func(want string) {
		t.Helper()
		a := c.AssessUbuntu(ctx, m, b, now)
		if a.Status != want {
			t.Fatalf("want %s: %+v", want, a)
		}
		if want != "unknown" && (len(a.Packages) != 1 || a.Packages[0].Fixed != "1:9.6p1-3ubuntu13.3" || a.AgentID != "owner") {
			t.Fatal(a)
		}
	}
	check("fixed")
	b.Snapshot.Components[0].SourceVersion = "1:9.6p1-3ubuntu13.2"
	check("affected")
	b.Snapshot.Components[0].SourceVersion = "1:9.6p1-3ubuntu13.3"
	check("fixed")
	b.Snapshot.Components[0].Name = "openssh-client"
	check("unknown")
	b.Snapshot.Components[0].Name = "openssh-server"
	b.Snapshot.Components[0].SourceVersion = ""
	check("unknown")
	b.Snapshot.Components[0].SourceVersion = "1:9.6p1-3ubuntu13.20"
	b.Snapshot.OS.Version = "26.04"
	check("unknown")
	b.Snapshot.OS.Version = "24.04"
	b.Snapshot.CollectedAt = now.Add(-25 * time.Hour)
	check("unknown")
	b.Snapshot.CollectedAt = now
	b.Link.State = "ambiguous"
	check("unknown")
	b.Link.State = "linked"
	b.Snapshot.Coverage[0].Status = "partial"
	check("unknown")
	b.Snapshot.Coverage[0].Status = "complete"
	cache.At = now.Add(-25 * time.Hour)
	put()
	check("unknown")
	cache.At = now
	cache.Error = "HTTP 503"
	put()
	check("unknown")
	cache.Error = ""
	cache.Record.Affected[0].Package.Ecosystem = "Ubuntu:24.04:Pro"
	put()
	check("unknown")
	cache.Record = record
	// A shallow copy above shares the affected slice, restore from source.
	json.Unmarshal([]byte(ubuntuFixture), &cache.Record)
	cache.Record.Affected[0].Ranges[0].Events = cache.Record.Affected[0].Ranges[0].Events[:1]
	put()
	check("unknown")
	json.Unmarshal([]byte(ubuntuFixture), &cache.Record)
	cache.Record.Withdrawn = &now
	put()
	check("unknown")
	cache.Record.Withdrawn = nil
	put()
	m.CVEs = []string{"CVE-2024-99999"}
	check("unknown")
}
func TestUbuntuOSVRejectsWrongIdentity(t *testing.T) {
	if _, e := parseUbuntu([]byte(ubuntuFixture), "CVE-2024-9999"); e == nil {
		t.Fatal("wrong CVE accepted")
	}
	if _, e := parseUbuntu([]byte(`{}`), "CVE-2024-6387"); e == nil {
		t.Fatal("empty accepted")
	}
}

type ubuntuRoundTrip func(*http.Request) (*http.Response, error)

func (f ubuntuRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestUbuntuSyncBoundsCachingAndFailedRefresh(t *testing.T) {
	c := fixture(t)
	ctx := context.Background()
	old := ubuntuClient
	defer func() { ubuntuClient = old }()
	calls := 0
	status := 200
	ubuntuClient = &http.Client{Transport: ubuntuRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != ubuntuURL("CVE-2024-6387") {
			t.Fatal("unexpected destination", r.URL)
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(ubuntuFixture)), Header: make(http.Header)}, nil
	})}
	c.SyncUbuntu(ctx, []string{"CVE-2024-6387", "CVE-2024-6387", "http://127.0.0.1/secret"})
	a := c.ubuntuCache(ctx, "CVE-2024-6387")
	if calls != 1 || a.At.IsZero() || len(a.SHA256) != 64 {
		t.Fatal(calls, a)
	}
	c.SyncUbuntu(ctx, []string{"CVE-2024-6387"})
	if calls != 1 {
		t.Fatal("cache ignored")
	}
	status = 503
	c.Request()
	c.SyncUbuntu(ctx, []string{"CVE-2024-6387"})
	b := c.ubuntuCache(ctx, "CVE-2024-6387")
	if calls != 2 || b.Error == "" || b.SHA256 != a.SHA256 || !b.At.Equal(a.At) {
		t.Fatal(calls, b)
	}
	c.SyncUbuntu(ctx, []string{"CVE-2024-6387"})
	if calls != 2 {
		t.Fatal("error retry throttling ignored")
	}
}
