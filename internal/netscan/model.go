// SPDX-License-Identifier: Apache-2.0
// Package netscan implements bounded, typed network discovery assignments.
package netscan

import (
	"fmt"
	"github.com/rkislov/cerber/internal/vuln"
	"net/netip"
	"time"
)

type Plan struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Agent    string    `json:"agent"`
	CIDR     string    `json:"cidr"`
	Profile  string    `json:"profile"`
	Interval int       `json:"interval_minutes"`
	Enabled  bool      `json:"enabled"`
	Next     time.Time `json:"next"`
	Cursor   string    `json:"cursor"`
}

func (p Plan) Validate() error {
	prefix, e := netip.ParsePrefix(p.CIDR)
	if e != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() || len(p.Name) < 1 || len(p.Name) > 120 || p.Interval < 15 || p.Interval > 43200 || (p.Profile != "discovery" && p.Profile != "services" && p.Profile != "vulnerabilities") {
		return fmt.Errorf("invalid network plan")
	}
	return nil
}

// Window bounds each assignment independently of prefix size. Large prefixes advance
// across successive runs; unvisited addresses are never described as absent.
func Window(cidr, cursor string) ([]string, string, error) {
	p, e := netip.ParsePrefix(cidr)
	if e != nil {
		return nil, "", e
	}
	p = p.Masked()
	a := p.Addr()
	if cursor != "" {
		a, e = netip.ParseAddr(cursor)
		if e != nil || !p.Contains(a) {
			return nil, "", fmt.Errorf("invalid cursor")
		}
	}
	out := []string{}
	for len(out) < 256 && a.IsValid() && p.Contains(a) {
		if a.IsGlobalUnicast() || a.IsLoopback() {
			out = append(out, a.String())
		} else {
			// Skip non-unicast blocks without iterating billions of addresses.
			skip := []string{"224.0.0.0/4", "169.254.0.0/16", "ff00::/8", "fe80::/10"}
			jumped := false
			for _, value := range skip {
				b := netip.MustParsePrefix(value)
				if b.Contains(a) {
					a = afterPrefix(b)
					jumped = true
					break
				}
			}
			if !jumped {
				a = a.Next()
			}
			continue
		}
		a = a.Next()
	}
	next := ""
	if a.IsValid() && p.Contains(a) {
		next = a.String()
	}
	if len(out) == 0 {
		return nil, "", fmt.Errorf("range contains no supported unicast targets")
	}
	return out, next, nil
}

type Task struct {
	ID      string    `json:"id"`
	Plan    string    `json:"plan"`
	Agent   string    `json:"agent"`
	CIDR    string    `json:"cidr"`
	Profile string    `json:"profile"`
	Targets []string  `json:"targets"`
	Expires time.Time `json:"expires"`
}

func (t Task) Validate() error {
	if len(t.ID) != 32 || len(t.Targets) < 1 || len(t.Targets) > 256 {
		return fmt.Errorf("invalid task")
	}
	p, e := netip.ParsePrefix(t.CIDR)
	if e != nil {
		return e
	}
	if t.Profile != "discovery" && t.Profile != "services" && t.Profile != "vulnerabilities" {
		return fmt.Errorf("invalid profile")
	}
	seen := map[string]bool{}
	for _, s := range t.Targets {
		a, e := netip.ParseAddr(s)
		if e != nil || a.Zone() != "" || !p.Contains(a) || seen[s] || !(a.IsGlobalUnicast() || a.IsLoopback()) {
			return fmt.Errorf("invalid target")
		}
		seen[s] = true
	}
	return nil
}

type Service struct {
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	Name     string   `json:"name"`
	Product  string   `json:"product"`
	Version  string   `json:"version"`
	CPE      []string `json:"cpe"`
}
type Finding struct {
	Script   string `json:"script"`
	Status   string `json:"status"`
	Evidence string `json:"evidence"`
}
type Host struct {
	Inventory       *vuln.InventoryLink `json:"inventory,omitempty"`
	Vulnerabilities []vuln.Match        `json:"vulnerabilities,omitempty"`
	IP              string              `json:"ip"`
	Name            string              `json:"name"`
	Services        []Service           `json:"services"`
	Findings        []Finding           `json:"findings"`
}
type Result struct {
	ID       string    `json:"id"`
	State    string    `json:"state"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Error    string    `json:"error"`
	Hosts    []Host    `json:"hosts"`
}
type Run struct {
	Task    Task      `json:"task"`
	Result  Result    `json:"result"`
	Created time.Time `json:"created"`
}
type Asset struct {
	Plan    string    `json:"plan"`
	Agent   string    `json:"agent"`
	Host    Host      `json:"host"`
	First   time.Time `json:"first_seen"`
	Last    time.Time `json:"last_seen"`
	Changed time.Time `json:"changed"`
	State   string    `json:"state"`
	New     bool      `json:"new"`
}

func afterPrefix(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr()
	if a.Is4() {
		b := a.As4()
		for bit := p.Bits(); bit < 32; bit++ {
			b[bit/8] |= 1 << uint(7-bit%8)
		}
		return netip.AddrFrom4(b).Next()
	}
	b := a.As16()
	for bit := p.Bits(); bit < 128; bit++ {
		b[bit/8] |= 1 << uint(7-bit%8)
	}
	return netip.AddrFrom16(b).Next()
}
