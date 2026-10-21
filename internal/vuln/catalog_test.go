// SPDX-License-Identifier: Apache-2.0
package vuln

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const xmlFixture = `<vulnerabilities><vul><identifier>BDU:2026-00001</identifier><name>OpenSSH test</name><description>Test fixture only</description><vulnerable_software><soft><name>OpenSSH</name><version>от 8.5p1 до 9.8p1</version></soft></vulnerable_software><cvss3><vector score="8.1">CVSS:3.1/AV:N</vector></cvss3><identifiers><identifier type="CVE">CVE-2026-12345</identifier></identifiers></vul></vulnerabilities>`

func fixture(t *testing.T) *Catalog {
	t.Helper()
	c, e := Open(filepath.Join(t.TempDir(), "catalog.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func TestBDUAtomicImportAndVersionBoundary(t *testing.T) {
	c := fixture(t)
	ctx := context.Background()
	if e := c.ImportBDU(ctx, strings.NewReader(xmlFixture)); e != nil {
		t.Fatal(e)
	}
	m := c.Lookup(ctx, "cpe:/a:openbsd:openssh:9.6p1")
	if len(m) != 1 || m[0].Score != 8.1 || m[0].Status != "version_candidate" {
		t.Fatal(m)
	}
	if len(c.Lookup(ctx, "cpe:/a:openbsd:openssh:9.8p1")) != 0 {
		t.Fatal("fixed boundary matched")
	}
	if len(c.Lookup(ctx, "cpe:/a:unrelated:openssh:9.6p1")) != 0 {
		t.Fatal("vendor not checked")
	}
	if e := c.ImportBDU(ctx, strings.NewReader(strings.TrimSuffix(xmlFixture, "</vulnerabilities>"))); e == nil {
		t.Fatal("incomplete import accepted")
	}
	if c.Status(ctx).BDUCount != 1 || len(c.BDU(ctx, "CVE-2026-12345")) != 1 {
		t.Fatal("prior snapshot lost")
	}
	if e := c.ImportBDU(ctx, strings.NewReader(`<vulnerabilities/>`)); e == nil {
		t.Fatal("empty replacement accepted")
	}
}
func TestVersionComparisonConservative(t *testing.T) {
	for _, v := range []struct {
		version, rule string
		want          bool
	}{{"9.6p1", "до 9.8p1", true}, {"9.8p1", "до 9.8p1", false}, {"9.8p1", "до 9.8p1 включительно", true}, {"9.6p1", "9.6.1", false}, {"9.6p1 Ubuntu fix", "до 9.8p1", false}, {"1.0.1i", "до 1.0.1j", false}, {"9.6p1", "от 10.0 до 11.0", false}} {
		if got := affected(v.version, v.rule); got != v.want {
			t.Fatal(v, got)
		}
	}
}
func TestCPERequiresConcreteIdentity(t *testing.T) {
	for _, raw := range []string{"cpe:/a:openbsd:openssh", "cpe:/o:linux:linux_kernel:6.8", "cpe:/a:openbsd:openssh:*", "--script=all", "https://localhost/private"} {
		if CPE(raw) != "" {
			t.Fatal(raw)
		}
	}
	if CPE("cpe:/a:openbsd:openssh:9.6p1") != "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*" {
		t.Fatal("conversion")
	}
}
func TestNVDMetricsAndCrossReferenceDedup(t *testing.T) {
	data := []byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-12345","descriptions":[{"lang":"en","value":"Fixture"}],"metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":9.8,"vectorString":"CVSS:3.1/AV:N"}}]}}}]}`)
	key := CPE("cpe:/a:openbsd:openssh:9.6p1")
	records, total, e := parseNVD(data, key)
	if e != nil || total != 1 || len(records) != 1 || records[0].Severity != "critical" {
		t.Fatal(records, e)
	}
	if _, _, e = parseNVD([]byte(`{}`), key); e == nil {
		t.Fatal("bad schema accepted")
	}
	c := fixture(t)
	ctx := context.Background()
	if e = c.ImportBDU(ctx, strings.NewReader(xmlFixture)); e != nil {
		t.Fatal(e)
	}
	cache := Cache{At: time.Now().Add(-48 * time.Hour), Records: records}
	b, _ := json.Marshal(cache)
	if _, e = c.db.Exec("INSERT INTO products VALUES(?,?)", key, string(b)); e != nil {
		t.Fatal(e)
	}
	matches := c.Lookup(ctx, key)
	if len(matches) != 1 || len(matches[0].BDU) != 1 || !matches[0].Stale {
		t.Fatal(matches)
	}
}

func TestNVDApplicabilityKeepsEnvironmentUncertainAndRejectsFixedVersion(t *testing.T) {
	key := CPE("cpe:/a:openbsd:openssh:9.6p1")
	m := cpeMatch{Vulnerable: true, Criteria: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", StartIncluding: "8.5p1", EndExcluding: "9.8p1"}
	nodes := []nvdNode{{Nodes: []nvdNode{{Operator: "OR", Matches: []cpeMatch{m}}}}}
	ok, conditional, _ := applicability(nodes, key, "")
	if !ok || conditional {
		t.Fatal(ok, conditional)
	}
	nodes[0].Operator = "AND"
	ok, conditional, _ = applicability(nodes, key, "")
	if !ok || !conditional {
		t.Fatal("environment treated as verified")
	}
	nodes[0].Operator = ""
	ok, conditional, _ = applicability(nodes, key, "This outcome occurs only on the client side.")
	if !ok || !conditional {
		t.Fatal("client-only treated as server proof")
	}
	nodes[0].Nodes[0].Matches[0].EndExcluding = "9.6p1"
	if ok, _, _ := applicability(nodes, key, ""); ok {
		t.Fatal("fixed version candidate")
	}
}

func TestCWEExtractionFromBDUAndNVD(t *testing.T) {
	c := fixture(t)
	xml := strings.Replace(xmlFixture, "<name>OpenSSH test</name>", "<name>OpenSSH test</name><cwes><cwe><identifier>CWE-362</identifier></cwe></cwes>", 1)
	if e := c.ImportBDU(context.Background(), strings.NewReader(xml)); e != nil {
		t.Fatal(e)
	}
	m := c.Lookup(context.Background(), "cpe:/a:openbsd:openssh:9.6p1")
	if len(m) != 1 || len(m[0].CWEs) != 1 || m[0].CWEs[0] != "CWE-362" {
		t.Fatal(m)
	}
	records, _, e := parseNVD([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-12345","weaknesses":[{"description":[{"value":"CWE-79"},{"value":"NVD-CWE-noinfo"}]}]}}]}`), CPE("cpe:/a:openbsd:openssh:9.6p1"))
	if e != nil || len(records) != 1 || len(records[0].CWEs) != 1 || records[0].CWEs[0] != "CWE-79" {
		t.Fatal(records, e)
	}
}
