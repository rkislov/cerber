// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"net/netip"
	"strconv"
	"strings"
)

// Only trusted kernel transport qualifies; SYSLOG_IDENTIFIER alone is forgeable.
// Custom prefixes are an operator contract: LOG must accompany the same verdict.
func normalizeNetfilter(n *Normalized, transport, host, message string) bool {
	if transport != "kernel" {
		return false
	}
	product, action, code := "", "", ""
	for _, p := range []struct{ prefix, product, action string }{
		{"[UFW BLOCK] ", "linux/ufw", "deny"},
		{"[UFW REJECT] ", "linux/ufw", "deny"},
		{"[UFW ALLOW] ", "linux/ufw", "allow"},
		{"CERBER_IPT_SYN ", "linux/iptables", "syn"},
		{"CERBER_NFT_SYN ", "linux/nftables", "syn"},
		{"CERBER_IPT_DROP ", "linux/iptables", "deny"},
		{"CERBER_NFT_DROP ", "linux/nftables", "deny"},
		{"CERBER_IPT_ACCEPT ", "linux/iptables", "allow"},
		{"CERBER_NFT_ACCEPT ", "linux/nftables", "allow"},
	} {
		if strings.HasPrefix(message, p.prefix) {
			product, action, code = p.product, p.action, strings.TrimSpace(p.prefix)
			break
		}
	}
	if product == "" {
		return false
	}
	fields := map[string]string{}
	for _, token := range strings.Fields(message) {
		key, value, ok := strings.Cut(token, "=")
		if ok {
			if _, exists := fields[key]; exists {
				n.Status = "quarantine"
				n.Class = "unknown"
				return true
			}
			fields[key] = value
		}
	}
	src, e1 := netip.ParseAddr(fields["SRC"])
	dst, e2 := netip.ParseAddr(fields["DST"])
	if e1 != nil || e2 != nil {
		n.Status = "quarantine"
		n.Class = "unknown"
		return true
	}
	n.Parser = "netfilter/2"
	n.Class = "firewall"
	n.Action = action
	n.Outcome = "unknown"
	if action == "deny" {
		n.Outcome = "failure"
	}
	if action == "allow" {
		n.Outcome = "success"
	}
	n.Product = product
	n.Device = host
	n.Code = code
	n.SourceIP = src.Unmap().String()
	n.DestinationIP = dst.Unmap().String()
	if port := fields["DPT"]; port != "" {
		p, e := strconv.Atoi(port)
		if e != nil || p < 1 || p > 65535 {
			n.Status = "quarantine"
			n.Class = "unknown"
			return true
		}
		n.DestinationPort = p
	}
	return true
}
