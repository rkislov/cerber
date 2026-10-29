// SPDX-License-Identifier: Apache-2.0
// Package rulepolicy defines bounded settings for built-in correlation rules.
package rulepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrInvalid = errors.New("invalid correlation policy")
var ErrConflict = errors.New("correlation policy version changed")
var ErrNotFound = errors.New("correlation policy version not found")

type Config struct {
	ExcludeDestinationCIDRs []string `json:"exclude_destination_cidrs"`
	Enabled                 bool     `json:"enabled"`
	Threshold               int      `json:"threshold"`
	WindowSeconds           int      `json:"window_seconds"`
	SuppressionSeconds      int      `json:"suppression_seconds"`
	GroupIDs                []string `json:"group_ids"`
	ExcludeAgents           []string `json:"exclude_agents"`
	ExcludeUsers            []string `json:"exclude_users"`
	ExcludeSourceCIDRs      []string `json:"exclude_source_cidrs"`
}
type Version struct {
	Rule         string    `json:"rule"`
	Revision     int64     `json:"revision"`
	Config       Config    `json:"config"`
	Actor        string    `json:"actor"`
	At           time.Time `json:"at"`
	Reason       string    `json:"reason"`
	RestoredFrom int64     `json:"restored_from,omitempty"`
}
type Applied struct {
	Revision      int64    `json:"revision"`
	Config        Config   `json:"config"`
	MatchedGroups []string `json:"matched_groups"`
	SHA256        string   `json:"sha256"`
}
type Change struct {
	Action           string `json:"action"`
	Rule             string `json:"rule"`
	ExpectedRevision int64  `json:"expected_revision"`
	Config           Config `json:"config"`
	TargetRevision   int64  `json:"target_revision,omitempty"`
	Reason           string `json:"reason"`
}

func Defaults() map[string]Config {
	out := map[string]Config{}
	for id, threshold := range map[string]int{"auth.repeated_failures": 5, "auth.success_after_failures": 5, "firewall.syn_scan": 20, "firewall.denied_burst": 20, "firewall.port_scan": 20, "fess.blocked_burst": 10, "fess.allowed_after_blocks": 5, "windows.audit_log_cleared": 1, "threatfox.ip_match": 1, "threatfox.ioc_match": 1} {
		window, suppression := 300, 300
		if id == "auth.success_after_failures" {
			suppression = 0
		}
		if Single(id) {
			window = 0
			suppression = 0
		}
		out[id] = Config{Enabled: true, Threshold: threshold, WindowSeconds: window, SuppressionSeconds: suppression, GroupIDs: []string{}, ExcludeAgents: []string{}, ExcludeUsers: []string{}, ExcludeSourceCIDRs: []string{}, ExcludeDestinationCIDRs: []string{}}
	}
	return out
}
func Single(id string) bool {
	return id == "windows.audit_log_cleared" || strings.HasPrefix(id, "threatfox.")
}
func Text(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func Canonical(rule string, c Config) (Config, error) {
	if _, ok := Defaults()[rule]; !ok {
		return c, ErrInvalid
	}
	if Single(rule) {
		if c.Threshold != 1 || c.WindowSeconds != 0 || c.SuppressionSeconds != 0 {
			return c, ErrInvalid
		}
	} else if c.Threshold < 1 || c.Threshold > 100 || c.WindowSeconds < 10 || c.WindowSeconds > 3600 || c.SuppressionSeconds < 0 || c.SuppressionSeconds > 3600 {
		return c, ErrInvalid
	}
	lists := []*[]string{&c.GroupIDs, &c.ExcludeAgents, &c.ExcludeUsers, &c.ExcludeSourceCIDRs, &c.ExcludeDestinationCIDRs}
	for i, list := range lists {
		if len(*list) > 32 {
			return c, ErrInvalid
		}
		out := []string{}
		seen := map[string]bool{}
		for _, raw := range *list {
			v := strings.TrimSpace(raw)
			if !Text(v, 256) {
				return c, ErrInvalid
			}
			if i == 0 {
				if len(v) != 32 && len(v) != 64 {
					return c, ErrInvalid
				}
				if _, e := hex.DecodeString(v); e != nil {
					return c, ErrInvalid
				}
			}
			if i == 2 {
				v = strings.ToLower(v)
			}
			if i >= 3 {
				p, e := netip.ParsePrefix(v)
				if e != nil {
					ip, err := netip.ParseAddr(v)
					if err != nil || ip.Zone() != "" {
						return c, ErrInvalid
					}
					ip = ip.Unmap()
					p = netip.PrefixFrom(ip, ip.BitLen())
				}
				if p.Addr().Is4In6() {
					return c, ErrInvalid
				}
				v = p.Masked().String()
			}
			if seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
		sort.Strings(out)
		*list = out
	}
	return c, nil
}
func Scope(c Config, agent, user, sourceIP string, groups []string) ([]string, string) {
	if !c.Enabled {
		return nil, "Правило выключено"
	}
	for _, id := range c.ExcludeAgents {
		if id == agent {
			return nil, "Агент исключён"
		}
	}
	for _, u := range c.ExcludeUsers {
		if u == strings.ToLower(user) {
			return nil, "Пользователь исключён"
		}
	}
	ip, e := netip.ParseAddr(sourceIP)
	if e == nil {
		for _, raw := range c.ExcludeSourceCIDRs {
			p, _ := netip.ParsePrefix(raw)
			if p.Contains(ip.Unmap()) {
				return nil, "IP источника исключён"
			}
		}
	}
	matched := []string{}
	for _, id := range c.GroupIDs {
		for _, g := range groups {
			if g == id {
				matched = append(matched, id)
				break
			}
		}
	}
	if len(c.GroupIDs) > 0 && len(matched) == 0 {
		return nil, "Агент не входит в выбранные группы"
	}
	return matched, ""
}
func Application(v Version, groups []string) *Applied {
	p, _ := json.Marshal(v.Config)
	sum := sha256.Sum256(p)
	return &Applied{Revision: v.Revision, Config: v.Config, MatchedGroups: groups, SHA256: hex.EncodeToString(sum[:])}
}

func ScopeEvent(c Config, agent, user, sourceIP, destinationIP string, groups []string) ([]string, string) {
	matched, reason := Scope(c, agent, user, sourceIP, groups)
	if reason != "" {
		return matched, reason
	}
	if ip, e := netip.ParseAddr(destinationIP); e == nil {
		for _, raw := range c.ExcludeDestinationCIDRs {
			p, _ := netip.ParsePrefix(raw)
			if p.Contains(ip.Unmap()) {
				return nil, "IP назначения исключён"
			}
		}
	}
	return matched, ""
}
