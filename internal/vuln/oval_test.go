// SPDX-License-Identifier: Apache-2.0
package vuln

import (
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/inventory"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const ovalFixture = `<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:l="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" xmlns:c="http://oval.mitre.org/XMLSchema/oval-common-5"><generator><c:timestamp>2026-01-01T00:00:00Z</c:timestamp></generator><definitions><definition id="oval:fixture:def:1" class="vulnerability"><metadata><affected><platform>RED OS 8.0</platform></affected><reference source="CVE" ref_id="CVE-2024-6387"/></metadata><criteria operator="OR"><criterion test_ref="t1"/><criterion test_ref="t2"/></criteria></definition></definitions><tests><l:rpminfo_test id="t1" check="all" check_existence="at_least_one_exists"><l:object object_ref="o1"/><l:state state_ref="s1"/></l:rpminfo_test><l:rpminfo_test id="t2" check="all" check_existence="at_least_one_exists"><l:object object_ref="o2"/><l:state state_ref="s1"/></l:rpminfo_test></tests><objects><l:rpminfo_object id="o1"><l:name>openssh-server</l:name></l:rpminfo_object><l:rpminfo_object id="o2"><l:name>openssh-clients</l:name></l:rpminfo_object></objects><states><l:rpminfo_state id="s1"><l:evr datatype="evr_string" operation="less than">0:9.6p1-3.red80</l:evr></l:rpminfo_state></states></oval_definitions>`

func TestRPMOrdering(t *testing.T) {
	for _, p := range []struct {
		a, b string
		want int
	}{{"0:9.6p1-13.red80", "0:9.6p1-3.red80", 1}, {"1:1-1", "0:99-99", 1}, {"1.0~rc1-1", "1.0-1", -1}, {"1.0^git-1", "1.0-1", 1}, {"1.0^git-1", "1.0.1-1", -1}, {"1.0-01", "0:1.0-1", 0}, {"1.0+git-1", "1.0.1-1", -1}, {"1+0-1", "1.0-1", 0}, {"1.0a-1", "1.0.1-1", -1}, {"1.0.0-1", "1.0-1", 1}} {
		n, e := CompareRPM(p.a, p.b)
		if e != nil || n < 0 && p.want >= 0 || n > 0 && p.want <= 0 || n == 0 && p.want != 0 {
			t.Fatalf("%+v got %d %v", p, n, e)
		}
	}
	for _, v := range []string{"1", "1.0-", "a:1-1", "1:1-2:3", "1.0-1;sh"} {
		if _, e := CompareRPM(v, "1-1"); e == nil {
			t.Fatal("accepted", v)
		}
	}
}
func TestOVALStrictConditions(t *testing.T) {
	src := ovalSources["redos-8"]
	r, _, e := parseOVAL(strings.NewReader(ovalFixture), src)
	if e != nil || r["CVE-2024-6387"].Unsupported || len(r["CVE-2024-6387"].Checks) != 2 {
		t.Fatal(r, e)
	}
	for _, replace := range [][2]string{{`operator="OR"`, `operator="AND"`}, {`test_ref="t1"`, `test_ref="t1" negate="true"`}, {`test_ref="t1"`, `test_ref="missing"`}, {`<criterion test_ref="t1"/>`, `<extend_definition definition_ref="x"/>`}, {`<criterion test_ref="t1"/>`, `<unknown/>`}, {`operation="less than"`, `operation="less than or equal"`}, {`<l:name>openssh-server</l:name>`, `<l:name operation="pattern match">openssh.*</l:name>`}, {`RED OS 8.0`, `RED OS 7.3`}, {`<l:evr datatype=`, `<l:arch>x86_64</l:arch><l:evr datatype=`}, {`class="vulnerability"`, `class="patch"`}} {
		v, _, e := parseOVAL(strings.NewReader(strings.Replace(ovalFixture, replace[0], replace[1], 1)), src)
		if e == nil && !v["CVE-2024-6387"].Unsupported {
			t.Fatal("condition dropped", replace, v)
		}
	}
	for _, xml := range []string{`<!DOCTYPE oval [<!ENTITY e SYSTEM "file:///etc/passwd">]>` + ovalFixture, strings.Replace(ovalFixture, `<l:rpminfo_object id="o1">`, `<l:rpminfo_object id="o2">`, 1), ovalFixture + `<extra/>`, strings.TrimSuffix(ovalFixture, "</oval_definitions>"), `<oval_definitions/>`} {
		if _, _, e := parseOVAL(strings.NewReader(xml), src); e == nil {
			t.Fatal("invalid feed accepted")
		}
	}
}
func TestOVALPackageEvidenceAllInstalledEVRs(t *testing.T) {
	c := fixture(t)
	ctx := context.Background()
	now := time.Now()
	src := ovalSources["redos-8"]
	records, modified, e := parseOVAL(strings.NewReader(ovalFixture), src)
	if e != nil {
		t.Fatal(e)
	}
	status := OVALSourceStatus{ID: src.ID, URL: src.URL, At: now, Modified: modified, SHA256: "test"}
	p, _ := json.Marshal(status)
	c.db.Exec("INSERT INTO vendor_oval_sources VALUES(?,?)", src.ID, string(p))
	p, _ = json.Marshal(records["CVE-2024-6387"])
	c.db.Exec("INSERT INTO vendor_oval_records VALUES(?,?,?)", src.ID, "CVE-2024-6387", string(p))
	b := InventoryBinding{Link: InventoryLink{State: "linked"}, Snapshot: inventory.Snapshot{OS: inventory.OS{DistributionID: "redos", Version: "8.0"}, PackageManager: "dnf", CollectedAt: now, Coverage: []inventory.Coverage{{Section: "packages", Status: "complete"}}, Components: []inventory.Component{{Name: "openssh-server", Kind: "package", State: "installed", VersionScheme: "rpm", Source: "rpm-query", Version: "0:9.6p1-13.red80"}}}}
	m := Match{Record: Record{ID: "CVE-2024-6387"}, CPE: CPE("cpe:/a:openbsd:openssh:9.6p1")}
	check := func(want string) {
		t.Helper()
		a := c.AssessPackage(ctx, m, b, now)
		if a.Status != want {
			t.Fatalf("%s: %+v", want, a)
		}
	}
	check("fixed")
	b.Snapshot.Components[0].InstalledVersions = []string{"0:9.6p1-13.red80", "0:9.6p1-2.red80"}
	check("affected")
	b.Snapshot.Components[0].InstalledVersions = nil
	b.Snapshot.Components[0].Name = "openssh-clients"
	check("unknown")
	b.Snapshot.Components[0].Name = "openssh-server"
	b.Snapshot.OS.DistributionID = "almalinux"
	check("unknown")
	b.Snapshot.OS.DistributionID = "redos"
	b.Snapshot.CollectedAt = now.Add(-25 * time.Hour)
	check("unknown")
	b.Snapshot.CollectedAt = now
	status.Error = "download failed"
	p, _ = json.Marshal(status)
	c.db.Exec("UPDATE vendor_oval_sources SET payload=?", string(p))
	check("unknown")
}

// Explicit opt-in local smoke check against separately downloaded vendor data.
func TestOfficialOVALFixture(t *testing.T) {
	p := os.Getenv("CERBER_OVAL_FIXTURE")
	if p == "" {
		t.Skip("no local vendor feed")
	}
	src := ovalSources[os.Getenv("CERBER_OVAL_SOURCE")]
	f, e := os.Open(p)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	var r map[string]ovalRecord
	var modified time.Time
	if strings.HasPrefix(src.ID, "alt-") {
		r, modified, e = parseALTZip(f, src, t.TempDir())
	} else {
		r, modified, e = parseOVAL(f, src)
	}
	if e != nil {
		t.Fatal(e)
	}
	supported := 0
	for _, v := range r {
		if !v.Unsupported {
			supported++
		}
	}
	t.Logf("CVE records=%d supported=%d timestamp=%s", len(r), supported, modified)
	if supported == 0 {
		t.Fatal("no supported definitions")
	}
}

func TestOVALCacheRefreshPreservesLastSnapshot(t *testing.T) {
	c := fixture(t)
	ctx := context.Background()
	old := ovalClient
	defer func() { ovalClient = old }()
	calls := 0
	body := ovalFixture
	ovalClient = &http.Client{Transport: ubuntuRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != ovalSources["redos-8"].URL {
			t.Fatal("unexpected URL", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	b := InventoryBinding{Link: InventoryLink{State: "linked"}, Snapshot: inventory.Snapshot{OS: inventory.OS{DistributionID: "redos", Version: "8.0"}}}
	c.SyncOVAL(ctx, []InventoryBinding{b, b})
	status := c.ovalStatus(ctx, "redos-8")
	if calls != 1 || status.Records != 1 || len(status.SHA256) != 64 || status.Error != "" {
		t.Fatal(calls, status)
	}
	c.SyncOVAL(ctx, []InventoryBinding{b})
	if calls != 1 {
		t.Fatal("cache ignored")
	}
	body = strings.TrimSuffix(ovalFixture, "</oval_definitions>")
	c.Request()
	c.SyncOVAL(ctx, []InventoryBinding{b})
	after := c.ovalStatus(ctx, "redos-8")
	if after.Error == "" || after.SHA256 != status.SHA256 || !after.At.Equal(status.At) {
		t.Fatal(after)
	}
	var count int
	c.db.QueryRow("SELECT count(*) FROM vendor_oval_records WHERE source='redos-8'").Scan(&count)
	if count != 1 {
		t.Fatal("last snapshot lost")
	}
	c.SyncOVAL(ctx, []InventoryBinding{b})
	if calls != 2 {
		t.Fatal("error retry ignored")
	}
}
func TestAstraDoesNotUseRPMOrOtherArchitecture(t *testing.T) {
	src := ovalSources["astra-1.8-x86_64"]
	xml := strings.NewReplacer("RED OS 8.0", "Astra Linux 1.8", "rpminfo", "dpkginfo", "evr_string", "debian_evr_string", "0:9.6p1-3.red80", "1:9.6p1-3+deb12u1").Replace(ovalFixture)
	r, _, e := parseOVAL(strings.NewReader(xml), src)
	if e != nil || r["CVE-2024-6387"].Unsupported {
		t.Fatal(r, e)
	}
	if _, ok := sourceForInventory(inventory.Snapshot{OS: inventory.OS{DistributionID: "astra", Version: "1.8", Architecture: "aarch64"}}); ok {
		t.Fatal("x86 source applied to ARM")
	}
	if _, ok := sourceForInventory(inventory.Snapshot{OS: inventory.OS{DistributionID: "debian", IDLike: []string{"astra"}, Version: "1.8", Architecture: "x86_64"}}); ok {
		t.Fatal("derivative assigned vendor source")
	}
	if _, ok := sourceForInventory(inventory.Snapshot{OS: inventory.OS{DistributionID: "astra", Version: "1.8_x86-64", Architecture: "x86_64"}}); !ok {
		t.Fatal("official target missing")
	}
}
