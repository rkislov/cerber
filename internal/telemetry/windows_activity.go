// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"net/netip"
	"strconv"
	"strings"
)

type WindowsActivity struct {
	SourceAddress      string `json:"source_address,omitempty"`
	DestinationAddress string `json:"destination_address,omitempty"`
	SourcePort         string `json:"source_port,omitempty"`
	DestinationPort    string `json:"destination_port,omitempty"`
	Protocol           string `json:"protocol,omitempty"`
	Direction          string `json:"direction,omitempty"`
	Process            string `json:"process,omitempty"`
	ProcessID          string `json:"process_id,omitempty"`
	Parent             string `json:"parent,omitempty"`
	ParentID           string `json:"parent_id,omitempty"`
	CommandLine        string `json:"command_line,omitempty"`
	Name               string `json:"name,omitempty"`
	Image              string `json:"image,omitempty"`
	RunAs              string `json:"run_as,omitempty"`
	TargetSID          string `json:"target_sid,omitempty"`
	TargetLogonID      string `json:"target_logon_id,omitempty"`
}

func normalizeWindowsActivity(n *Normalized, f map[string]string, computer string, code int) {
	n.Parser = "windows-activity/1"
	n.Outcome = "success"
	n.Identity = windowsIdentity(f, computer, "Subject")
	n.User = f["SubjectUserName"]
	if d := f["SubjectDomainName"]; d != "" && n.User != "" {
		n.User = d + `\` + n.User
	}
	w := &WindowsActivity{}
	n.WindowsActivity = w
	switch code {
	case 4688:
		n.Class = "process"
		n.Action = "process_created"
		w.Process = f["NewProcessName"]
		w.ProcessID = WindowsPID(f["NewProcessId"])
		w.Parent = f["ParentProcessName"]
		w.ParentID = f["ProcessId"]
		w.CommandLine = f["CommandLine"]
		w.TargetSID = f["TargetUserSid"]
		w.TargetLogonID = f["TargetLogonId"]
	case 4689:
		n.Class = "process"
		n.Action = "process_exited"
		w.Process = f["ProcessName"]
		w.ProcessID = WindowsPID(f["ProcessId"])
	case 5156:
		n.Class = "network_connection"
		n.Action = "connection_permitted"
		n.Identity = &Identity{Computer: computer}
		n.User = ""
		w.Process = f["Application"]
		w.ProcessID = WindowsPID(f["ProcessID"])
		w.Protocol = f["Protocol"]
		w.Direction = f["Direction"]
		for key, target := range map[string]*string{"SourceAddress": &w.SourceAddress, "DestAddress": &w.DestinationAddress} {
			if ip, e := netip.ParseAddr(f[key]); e == nil && ip.Zone() == "" {
				*target = ip.Unmap().String()
			}
		}
		for key, target := range map[string]*string{"SourcePort": &w.SourcePort, "DestPort": &w.DestinationPort} {
			if v, e := strconv.ParseUint(f[key], 10, 16); e == nil && v > 0 {
				*target = strconv.FormatUint(v, 10)
			}
		}
		n.SourceIP = w.SourceAddress
		n.DestinationIP = w.DestinationAddress
		n.DestinationPort, _ = strconv.Atoi(w.DestinationPort)
	case 4697, 7045:
		n.Class = "service"
		n.Action = "service_installed"
		w.Name = f["ServiceName"]
		w.Image = f["ServiceFileName"]
		w.RunAs = f["ServiceAccount"]
		if code == 7045 {
			w.Image = f["ImagePath"]
			w.RunAs = f["AccountName"]
			n.Identity = &Identity{Computer: computer}
			n.User = ""
		}
	case 4698:
		n.Class = "task"
		n.Action = "task_created"
		w.Name = f["TaskName"]
	}
}

func WindowsPID(s string) string {
	base := 10
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		base = 16
		s = s[2:]
	}
	v, e := strconv.ParseUint(s, base, 32)
	if e != nil || v == 0 {
		return ""
	}
	return strconv.FormatUint(v, 10)
}
