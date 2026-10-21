//go:build linux

// SPDX-License-Identifier: Apache-2.0
package endpoint

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

func firewall(ctx context.Context, b Block, add bool) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if len(b.ID) != 32 {
		return ErrInvalid
	}
	for _, r := range b.ID {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return ErrInvalid
		}
	}
	name := "cerber_ar_" + b.ID
	path := "/usr/sbin/nft"
	if !add {
		cmd := exec.CommandContext(ctx, path, "delete", "table", "inet", name)
		if e := cmd.Run(); e != nil {
			out, listErr := exec.CommandContext(ctx, path, "list", "tables").Output()
			if listErr == nil && !strings.Contains(string(out), "table inet "+name) {
				return nil
			}
			return e
		}
		return nil
	}
	ip, e := netip.ParseAddr(b.IP)
	if e != nil || ip.Zone() != "" || !ip.IsGlobalUnicast() {
		return ErrInvalid
	}
	remaining := int(time.Until(b.Expires).Seconds())
	if remaining < 1 {
		return nil
	}
	if exec.CommandContext(ctx, path, "list", "table", "inet", name).Run() == nil {
		return nil
	}
	kind, selector := "ipv4_addr", "ip"
	if ip.Is6() {
		kind, selector = "ipv6_addr", "ip6"
	}
	script := fmt.Sprintf("table inet %s {\n set blocked { type %s; flags timeout; elements = { %s timeout %ds }; }\n chain input { type filter hook input priority -200; policy accept; %s saddr @blocked drop; }\n chain output { type filter hook output priority -200; policy accept; %s daddr @blocked drop; }\n}\n", name, kind, ip.String(), remaining, selector, selector)
	cmd := exec.CommandContext(ctx, path, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if cmd.Run() != nil {
		return fmt.Errorf("nftables response operation failed")
	}
	return nil
}
