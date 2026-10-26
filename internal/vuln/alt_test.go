// SPDX-License-Identifier: Apache-2.0
package vuln

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/inventory"
	"strings"
	"testing"
	"time"
)

func altFixture() string {
	doc := strings.NewReplacer("RED OS 8.0", "ALT Linux branch p11", "0:9.6p1-3.red80", "0:9.6p1-alt2", `class="vulnerability"`, `class="patch"`, `check_existence="at_least_one_exists"`, ``).Replace(ovalFixture)
	doc = strings.Replace(doc, `<criteria operator="OR"><criterion test_ref="t1"/><criterion test_ref="t2"/></criteria>`, `<criteria operator="AND"><criterion test_ref="guard"/><criteria operator="OR"><criterion test_ref="t1"/><criterion test_ref="t2"/></criteria></criteria>`, 1)
	const ns = `http://oval.mitre.org/XMLSchema/oval-definitions-5#independent`
	doc = strings.Replace(doc, "<tests>", `<tests><i:textfilecontent54_test xmlns:i="`+ns+`" id="guard" check="all"><i:object object_ref="guard-o"/><i:state state_ref="guard-s"/></i:textfilecontent54_test>`, 1)
	doc = strings.Replace(doc, "<objects>", `<objects><i:textfilecontent54_object xmlns:i="`+ns+`" id="guard-o"><i:path datatype="string">/etc</i:path><i:filename datatype="string">os-release</i:filename><i:pattern datatype="string" operation="pattern match">`+altCPEPattern+`</i:pattern><i:instance datatype="int">1</i:instance></i:textfilecontent54_object>`, 1)
	doc = strings.Replace(doc, "<states>", `<states><i:textfilecontent54_state xmlns:i="`+ns+`" id="guard-s"><i:subexpression operation="equals">11</i:subexpression></i:textfilecontent54_state>`, 1)
	return doc
}
func TestALTPlatformGuardNotIgnored(t *testing.T) {
	src := ovalSources["alt-p11"]
	records, _, e := parseOVAL(strings.NewReader(altFixture()), src)
	if e != nil || records["CVE-2024-6387"].Unsupported {
		t.Fatal(records, e)
	}
	for _, replace := range [][2]string{{">11</", ">10</"}, {"/etc", "/tmp"}, {"os-release", "altlinux-release"}, {altCPEPattern, ".*"}, {`test_ref="guard"`, `test_ref="other"`}, {`operator="AND"`, `operator="OR"`}, {`operation="equals"`, `operation="not equal"`}} {
		r, _, e := parseOVAL(strings.NewReader(strings.Replace(altFixture(), replace[0], replace[1], 1)), src)
		if e == nil && !r["CVE-2024-6387"].Unsupported {
			t.Fatal("platform condition lost", replace)
		}
	}
	for _, os := range []inventory.OS{{CPEName: "cpe:/o:alt:server:11", BranchID: "p11"}, {CPEName: "cpe:/o:alt:kworkstation:11.4"}} {
		if altBranch(os) != "p11" {
			t.Fatal(os)
		}
	}
	for _, os := range []inventory.OS{{Version: "11", BranchID: "p11"}, {CPEName: "cpe:/o:alt:spserver:11"}, {CPEName: "cpe:/o:alt:server:11", BranchID: "p10"}, {CPEName: "cpe:/o:alt:server:sisyphus"}} {
		if altBranch(os) != "" {
			t.Fatal(os)
		}
	}
}
func zipFixture(t *testing.T, name, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, e := z.Create(name)
	if e != nil {
		t.Fatal(e)
	}
	w.Write([]byte(body))
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func TestALTZipBoundsAndNoExtraction(t *testing.T) {
	src := ovalSources["alt-p11"]
	data := zipFixture(t, "ALT-PU-2024-1234.xml", altFixture())
	r, _, e := parseALTZip(bytes.NewReader(data), src, t.TempDir())
	if e != nil || r["CVE-2024-6387"].Unsupported {
		t.Fatal(r, e)
	}
	for _, name := range []string{"../../etc/passwd", "nested/ALT-PU-2024-1234.xml", "other.zip"} {
		if _, _, e = parseALTZip(bytes.NewReader(zipFixture(t, name, altFixture())), src, t.TempDir()); e == nil {
			t.Fatal("unsafe entry accepted", name)
		}
	}
	if _, _, e = parseALTZip(strings.NewReader("not zip"), src, t.TempDir()); e == nil {
		t.Fatal("invalid ZIP accepted")
	}
}

func TestALTPackageAssessmentNeedsDeclaredBranch(t *testing.T) {
	c := fixture(t)
	ctx := context.Background()
	now := time.Now()
	src := ovalSources["alt-p11"]
	r, modified, e := parseOVAL(strings.NewReader(altFixture()), src)
	if e != nil {
		t.Fatal(e)
	}
	status := OVALSourceStatus{ID: src.ID, URL: src.URL, At: now, Modified: modified}
	p, _ := json.Marshal(status)
	if _, e = c.db.Exec("INSERT INTO vendor_oval_sources VALUES(?,?)", src.ID, string(p)); e != nil {
		t.Fatal(e)
	}
	p, _ = json.Marshal(r["CVE-2024-6387"])
	c.db.Exec("INSERT INTO vendor_oval_records VALUES(?,?,?)", src.ID, "CVE-2024-6387", string(p))
	b := InventoryBinding{Link: InventoryLink{State: "linked"}, Snapshot: inventory.Snapshot{OS: inventory.OS{DistributionID: "altlinux", Version: "11.4", CPEName: "cpe:/o:alt:kworkstation:11", BranchID: "p11"}, PackageManager: "apt-rpm", CollectedAt: now, Coverage: []inventory.Coverage{{Section: "packages", Status: "complete"}}, Components: []inventory.Component{{Name: "openssh-server", Kind: "package", State: "installed", VersionScheme: "rpm", Source: "rpm-query", Version: "0:9.6p1-alt3"}}}}
	m := Match{Record: Record{ID: "CVE-2024-6387"}, CPE: CPE("cpe:/a:openbsd:openssh:9.6p1")}
	if a := c.AssessPackage(ctx, m, b, now); a.Status != "fixed" {
		t.Fatal(a)
	}
	b.Snapshot.OS.BranchID = "p10"
	if a := c.AssessPackage(ctx, m, b, now); a.Status != "unknown" {
		t.Fatal("wrong branch", a)
	}
	b.Snapshot.OS.BranchID = "p11"
	b.Snapshot.OS.CPEName = ""
	if a := c.AssessPackage(ctx, m, b, now); a.Status != "unknown" {
		t.Fatal("version used as branch", a)
	}
}
