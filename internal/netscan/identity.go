// SPDX-License-Identifier: Apache-2.0
package netscan

import (
	"github.com/rkislov/cerber/internal/vuln"
	"strings"
)

// Identities prefers scanner CPEs. A separately observed concrete version can fill
// a missing CPE version; only two reviewed name-only aliases are inferred.
func (s Service) Identities() []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(raw string) {
		if key := vuln.CPE(raw); key != "" && !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	for _, raw := range s.CPE {
		add(raw)
		if strings.HasPrefix(raw, "cpe:/a:") && len(strings.Split(raw, ":")) == 4 && s.Version != "" {
			add(raw + ":" + s.Version)
		}
	}
	if len(out) == 0 && s.Version != "" {
		switch strings.ToLower(strings.TrimSpace(s.Product)) {
		case "openssh":
			add("cpe:/a:openbsd:openssh:" + s.Version)
		case "apache httpd", "apache http server":
			add("cpe:/a:apache:http_server:" + s.Version)
		}
	}
	return out
}
