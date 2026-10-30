// SPDX-License-Identifier: Apache-2.0
package telemetry

type WindowsActivity struct {
	Process       string `json:"process,omitempty"`
	ProcessID     string `json:"process_id,omitempty"`
	Parent        string `json:"parent,omitempty"`
	ParentID      string `json:"parent_id,omitempty"`
	CommandLine   string `json:"command_line,omitempty"`
	Name          string `json:"name,omitempty"`
	Image         string `json:"image,omitempty"`
	RunAs         string `json:"run_as,omitempty"`
	TargetSID     string `json:"target_sid,omitempty"`
	TargetLogonID string `json:"target_logon_id,omitempty"`
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
		w.ProcessID = f["NewProcessId"]
		w.Parent = f["ParentProcessName"]
		w.ParentID = f["ProcessId"]
		w.CommandLine = f["CommandLine"]
		w.TargetSID = f["TargetUserSid"]
		w.TargetLogonID = f["TargetLogonId"]
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
