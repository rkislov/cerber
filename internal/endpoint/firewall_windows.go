//go:build windows

// SPDX-License-Identifier: Apache-2.0
package endpoint

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func firewall(ctx context.Context, b Block, add bool) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if len(b.ID) != 32 {
		return ErrInvalid
	}
	for _, r := range b.ID {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return ErrInvalid
		}
	}
	name := "CerberAR_" + b.ID
	root := os.Getenv("SystemRoot")
	if root == "" {
		return ErrInvalid
	}
	netsh := filepath.Join(root, "System32", "netsh.exe")
	ps := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if !add {
		script := "$ErrorActionPreference='Stop';Get-NetFirewallRule -DisplayName '" + name + "' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop; if(Get-ScheduledTask -TaskName '" + name + "' -ErrorAction SilentlyContinue){Unregister-ScheduledTask -TaskName '" + name + "' -Confirm:$false -ErrorAction Stop}"
		if exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", script).Run() != nil {
			return fmt.Errorf("Windows Firewall rollback failed")
		}
		return nil
	}

	ip, e := netip.ParseAddr(b.IP)
	if e != nil || ip.Zone() != "" || !ip.IsGlobalUnicast() {
		return ErrInvalid
	}
	script := fmt.Sprintf("$ErrorActionPreference='Stop';$a=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\\netsh.exe') -Argument 'advfirewall firewall delete rule name=%s';$t=New-ScheduledTaskTrigger -Once -At ([datetimeoffset]::Parse('%s').LocalDateTime);Register-ScheduledTask -TaskName '%s' -Action $a -Trigger $t -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable) -User SYSTEM -RunLevel Highest -Force | Out-Null", name, b.Expires.Format("2006-01-02T15:04:05Z07:00"), name)
	if exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", script).Run() != nil {
		return fmt.Errorf("Windows expiry task failed")
	}
	_ = exec.CommandContext(ctx, netsh, "advfirewall", "firewall", "delete", "rule", "name="+name).Run()
	for _, dir := range []string{"in", "out"} {
		if exec.CommandContext(ctx, netsh, "advfirewall", "firewall", "add", "rule", "name="+name, "dir="+dir, "action=block", "remoteip="+ip.String(), "enable=yes").Run() != nil {
			_ = firewall(ctx, b, false)
			return fmt.Errorf("Windows Firewall operation failed")
		}
	}
	return nil
}
