// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"strconv"
	"strings"
)

// WindowsAuth keeps the credential target / ticket principal separate from the
// initiating Identity. In 4769 ServiceSID belongs to the service, not the user.
type WindowsAuth struct {
	TargetAccount string `json:"target_account,omitempty"`
	AccountRef    string `json:"account_ref,omitempty"`
	TargetGUID    string `json:"target_guid,omitempty"`
	Service       string `json:"service,omitempty"`
	ServiceSID    string `json:"service_sid,omitempty"`
	Status        string `json:"status,omitempty"`
	Encryption    string `json:"encryption,omitempty"`
	TargetServer  string `json:"target_server,omitempty"`
	Process       string `json:"process,omitempty"`
	ProcessID     string `json:"process_id,omitempty"`
}

// WindowsAccountRef deliberately does not guess DNS/NetBIOS aliases or resolve
// names into SIDs. A qualified name is used only together with a nonzero GUID.
func WindowsAccountRef(name, realm, computer string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	realm = strings.ToLower(strings.TrimSpace(realm))
	computer = strings.ToLower(strings.TrimSpace(computer))
	if strings.Contains(name, "\\") {
		return ""
	}
	if strings.Count(name, "@") == 1 {
		parts := strings.Split(name, "@")
		if realm != "" && realm != "-" && realm != parts[1] {
			return ""
		}
		name, realm = parts[0], parts[1]
	} else if strings.Contains(name, "@") {
		return ""
	}
	if name == "" || name == "-" || strings.HasSuffix(name, "$") || realm == "" || realm == "-" || realm == "." || realm == "workgroup" || realm == "nt authority" || realm == "builtin" || realm == computer || realm == strings.Split(computer, ".")[0] {
		return ""
	}
	return realm + `\` + name
}
func normalizeWindowsAuth(n *Normalized, fields map[string]string, computer string, code int) {
	target := fields["TargetUserName"]
	realm := fields["TargetDomainName"]
	ref := WindowsAccountRef(target, realm, computer)
	display := target
	if realm != "" && realm != "-" && !strings.Contains(target, "@") {
		display = realm + `\` + target
	}
	display = strings.ToLower(display)
	n.WindowsAuth = &WindowsAuth{TargetAccount: display, AccountRef: ref}
	n.Parser = "windows-auth-flow/1"
	switch code {
	case 4648:
		n.Class = "credentials"
		n.Action = "explicit_credentials"
		n.Outcome = "unknown"
		n.Identity = windowsIdentity(fields, computer, "Subject")
		n.User = fields["SubjectUserName"]
		if d := fields["SubjectDomainName"]; d != "" && d != "-" && n.User != "" {
			n.User = d + `\` + n.User
		}
		n.WindowsAuth.TargetGUID = WindowsGUID(fields["TargetLogonGuid"])
		n.WindowsAuth.TargetServer = fields["TargetServerName"]
		n.WindowsAuth.Process = fields["ProcessName"]
		n.WindowsAuth.ProcessID = fields["ProcessId"]
	case 4769:
		n.Class = "kerberos"
		n.Action = "kerberos_service_ticket"
		n.Outcome = "unknown"
		n.User = display
		n.Identity = &Identity{Computer: strings.ToLower(computer), SessionGUID: WindowsGUID(fields["LogonGuid"])}
		n.WindowsAuth.Service = fields["ServiceName"]
		n.WindowsAuth.ServiceSID = fields["ServiceSid"]
		n.WindowsAuth.Status = fields["Status"]
		n.WindowsAuth.Encryption = fields["TicketEncryptionType"]
		raw := strings.ToLower(strings.TrimSpace(fields["Status"]))
		if strings.HasPrefix(raw, "0x") {
			if status, e := strconv.ParseUint(raw[2:], 16, 32); e == nil {
				if status == 0 {
					n.Outcome = "success"
				} else {
					n.Outcome = "failure"
				}
			}
		}
	}
	n.SourceIP = fields["IpAddress"]
}
