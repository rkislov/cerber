// SPDX-License-Identifier: Apache-2.0
package rulepolicy

import (
	"strings"
	"testing"
)

func TestPolicyCanonicalScopeAndLimits(t *testing.T) {
	c := Defaults()["auth.repeated_failures"]
	g := strings.Repeat("a", 32)
	c.GroupIDs = []string{g, g}
	c.ExcludeUsers = []string{` LAB\Alice `}
	c.ExcludeSourceCIDRs = []string{"192.0.2.9/24"}
	c, e := Canonical("auth.repeated_failures", c)
	if e != nil || len(c.GroupIDs) != 1 || c.ExcludeSourceCIDRs[0] != "192.0.2.0/24" {
		t.Fatal(c, e)
	}
	if _, why := Scope(c, "agent", `LAB\ALICE`, "198.51.100.1", []string{g}); why != "Пользователь исключён" {
		t.Fatal(why)
	}
	if _, why := Scope(c, "agent", "other", "::ffff:192.0.2.10", []string{g}); why != "IP источника исключён" {
		t.Fatal(why)
	}
	if _, why := Scope(c, "agent", "other", "198.51.100.1", nil); why != "Агент не входит в выбранные группы" {
		t.Fatal(why)
	}
	if matched, why := Scope(c, "agent", "other", "198.51.100.1", []string{g}); why != "" || len(matched) != 1 {
		t.Fatal(matched, why)
	}
	for _, change := range []func(*Config){func(c *Config) { c.Threshold = 101 }, func(c *Config) { c.WindowSeconds = 3601 }, func(c *Config) { c.ExcludeSourceCIDRs = []string{"not an IP"} }, func(c *Config) { c.GroupIDs = []string{"missing"} }} {
		bad := c
		change(&bad)
		if _, e := Canonical("auth.repeated_failures", bad); e == nil {
			t.Fatal(bad)
		}
	}
	single := Defaults()["threatfox.ioc_match"]
	single.Threshold = 2
	if _, e := Canonical("threatfox.ioc_match", single); e == nil {
		t.Fatal("IOC threshold accepted")
	}
}

func TestDestinationExclusionDoesNotBecomeSourceExclusion(t *testing.T) {
	c := Defaults()["threatfox.ioc_match"]
	c.ExcludeDestinationCIDRs = []string{"192.0.2.10"}
	c, e := Canonical("threatfox.ioc_match", c)
	if e != nil {
		t.Fatal(e)
	}
	if _, why := ScopeEvent(c, "agent", "", "198.51.100.1", "192.0.2.10", nil); why != "IP назначения исключён" {
		t.Fatal(why)
	}
	if _, why := ScopeEvent(c, "agent", "", "192.0.2.10", "198.51.100.1", nil); why != "" {
		t.Fatal(why)
	}
}
