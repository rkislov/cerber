// SPDX-License-Identifier: Apache-2.0
package netscan

import (
	"net/netip"
	"strings"
	"testing"
)

func task() Task {
	return Task{ID: strings.Repeat("a", 32), CIDR: "192.0.2.0/24", Targets: []string{"192.0.2.1"}, Profile: "vulnerabilities"}
}
func TestWindowAnyCIDRBounded(t *testing.T) {
	for _, cidr := range []string{"192.0.2.1/32", "10.0.0.0/8", "2001:db8::/32", "0.0.0.0/0", "::/0"} {
		a, next, e := Window(cidr, "")
		if e != nil || len(a) == 0 || len(a) > 256 {
			t.Fatalf("%s %v", cidr, e)
		}
		if next != "" {
			b, _, e := Window(cidr, next)
			if e != nil || b[0] == a[0] {
				t.Fatal("cursor did not advance")
			}
		}
	}
	if _, _, e := Window("224.0.0.0/4", ""); e == nil {
		t.Fatal("multicast accepted")
	}
	if afterPrefix(netip.MustParsePrefix("169.254.0.0/16")).String() != "169.255.0.0" {
		t.Fatal("prefix skip")
	}
}
func TestArgsConstrained(t *testing.T) {
	v := task()
	a, e := Args(v)
	if e != nil || !strings.Contains(strings.Join(a, " "), Scripts) {
		t.Fatal(a, e)
	}
	v.Targets = []string{"--script=all"}
	if _, e = Args(v); e == nil {
		t.Fatal("argument injection")
	}
	v = task()
	v.Targets = []string{"198.51.100.1"}
	if _, e = Args(v); e == nil {
		t.Fatal("out of scope")
	}
}
func TestXMLStructuredVulnerabilityAndNoFalseHost(t *testing.T) {
	xml := `<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port portid="445" protocol="tcp"><state state="open"/><service name="microsoft-ds"/><script id="smb-vuln-ms17-010" output="evidence"><table key="CVE-2017-0143"><elem key="state">VULNERABLE</elem></table></script></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`
	h, e := Parse([]byte(xml), task())
	if e != nil || len(h) != 1 || h[0].Findings[0].Status != "scanner_confirmed" {
		t.Fatal(h, e)
	}
	h, e = Parse([]byte(strings.ReplaceAll(xml, `state="open"`, `state="closed"`)), task())
	if e != nil || len(h) != 0 {
		t.Fatal("-Pn false host", h, e)
	}
	if _, e = Parse([]byte(strings.ReplaceAll(xml, `<host>`, `<host timedout="true">`)), task()); e == nil {
		t.Fatal("partial treated as complete")
	}
	if _, e = Parse([]byte(strings.ReplaceAll(xml, "192.0.2.1", "198.51.100.1")), task()); e == nil {
		t.Fatal("out of scope result")
	}
	h, e = Parse([]byte(strings.ReplaceAll(xml, ">VULNERABLE<", ">LIKELY VULNERABLE<")), task())
	if e != nil || h[0].Findings[0].Status == "scanner_confirmed" {
		t.Fatal("hypothesis confirmed")
	}
}

func TestExpandedSafeScriptStructuredResult(t *testing.T) {
	xml := `<nmaprun><host><status state="up"/><address addr="192.0.2.1"/><ports><port portid="80" protocol="tcp"><state state="open"/><script id="http-vuln-cve2015-1635" output="fixture"><table><elem key="state">VULNERABLE (Exploitable)</elem></table></script></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`
	h, e := Parse([]byte(xml), task())
	if e != nil || len(h) != 1 || len(h[0].Findings) != 1 || h[0].Findings[0].Status != "scanner_confirmed" {
		t.Fatal(h, e)
	}
}

func TestServiceIdentityRequiresConcreteVersion(t *testing.T) {
	s := Service{Product: "OpenSSH", Version: "9.6p1"}
	if len(s.Identities()) != 1 {
		t.Fatal(s.Identities())
	}
	s.Version = ""
	if len(s.Identities()) != 0 {
		t.Fatal("unknown version inferred")
	}
	s = Service{CPE: []string{"cpe:/a:apache:http_server"}, Version: "2.4.58"}
	if len(s.Identities()) != 1 {
		t.Fatal("CPE version not filled")
	}
	s.Version = "2.4.58 custom fix"
	if len(s.Identities()) != 0 {
		t.Fatal("ambiguous version accepted")
	}
}
