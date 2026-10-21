// SPDX-License-Identifier: Apache-2.0
package attack

import (
	"strings"
	"testing"
)

func TestCatalogCurrentIdentitiesAndNoRetiredLogClear(t *testing.T) {
	c := Catalog()
	if c.Retrieved != "2026-10-21" || len(c.SHA256) != 64 {
		t.Fatal(c)
	}
	a := Rule("windows.audit_log_cleared")
	if len(a.Techniques) != 1 || a.Techniques[0].ID != "T1685.005" || a.Techniques[0].Tactics[0].ID != "TA0112" {
		t.Fatal(a)
	}
	for _, v := range c.Techniques {
		if v.ID == "T1070.001" || !strings.HasPrefix(v.URL, "https://attack.mitre.org/") {
			t.Fatal(v)
		}
	}
}
func TestNoTechniqueFromOneLoginOrGenericWAFOrIOC(t *testing.T) {
	for _, a := range []*Assessment{Event("authentication", "", "success", "parsed"), Event("fess", "allow", "", "parsed"), Rule("fess.allowed_after_blocks"), Rule("threatfox.ioc_match")} {
		if a == nil || len(a.Techniques) != 0 || len(a.Effects) == 0 {
			t.Fatal(a)
		}
	}
	if RuleVersion("auth.repeated_failures", 99) != nil || Rule("unknown") != nil {
		t.Fatal("invented mapping")
	}
	if Event("audit", "log_cleared", "", "quarantine") != nil {
		t.Fatal("quarantine mapped")
	}
}
func TestVulnerabilityCIAIsPotentialNotArbitraryATTACK(t *testing.T) {
	a := Vulnerability([]string{"CVE-2026-123456"}, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "version_candidate")
	if len(a.Techniques) != 0 || len(a.Effects) != 2 || a.Effects[0].Kind != "confidentiality" || a.Effects[1].Kind != "integrity" {
		t.Fatal(a)
	}
	a = Vulnerability(nil, "CVSS:4.0/AV:N/VC:H/VI:N/VA:L/SC:H/SI:N/SA:N", "context_required")
	if len(a.Effects) != 3 || !strings.Contains(a.Observation, "условия") {
		t.Fatal(a)
	}
}
func TestCuratedVulnerabilityScenariosRemainConditional(t *testing.T) {
	for _, status := range []string{"version_candidate", "context_required", "scanner_confirmed"} {
		a := Vulnerability([]string{"CVE-2024-6387"}, "", status)
		if len(a.Techniques) != 2 || a.Kind != "vulnerability_scenario" {
			t.Fatal(a)
		}
		for _, x := range a.Techniques {
			if x.Condition == "" {
				t.Fatal(x)
			}
		}
		if strings.Contains(a.Observation, "эксплуатация подтверждена") {
			t.Fatal("upgrade to compromise")
		}
	}
	a := Vulnerability([]string{"CVE-2014-0160"}, "", "scanner_confirmed")
	if len(a.Techniques) != 0 || a.Effects[0].Kind != "memory_disclosure" {
		t.Fatal(a)
	}
}

func TestMultipleCVEAliasesDoNotDuplicateTechniqueCounts(t *testing.T) {
	a := Vulnerability([]string{"CVE-2024-6387", "CVE-2015-1635"}, "", "version_candidate")
	if len(a.Techniques) != 2 {
		t.Fatal(a.Techniques)
	}
}
