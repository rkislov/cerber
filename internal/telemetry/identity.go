// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Identity contains source-reported identifiers, not directory attestation.
// LocalSession is scoped to AgentID + AssetID and must never join hosts alone.
type Identity struct {
	AccountRef   string `json:"account_ref,omitempty"`
	AccountKey   string `json:"account_key,omitempty"`
	AccountSID   string `json:"account_sid,omitempty"`
	Realm        string `json:"realm,omitempty"`
	SessionGUID  string `json:"session_guid,omitempty"`
	LocalSession string `json:"local_session,omitempty"`
	SSHKey       string `json:"ssh_key,omitempty"`
	Computer     string `json:"computer,omitempty"`
	LogonType    int    `json:"logon_type,omitempty"`
}

var accountSID = regexp.MustCompile(`^S-1-5-21-([0-9]+)-([0-9]+)-([0-9]+)-([0-9]+)$`)
var sshFingerprint = regexp.MustCompile(`\bSHA256:([A-Za-z0-9+/]{43})(?:\s|$)`)

func windowsIdentity(fields map[string]string, computer, prefix string) *Identity {
	i := &Identity{Computer: strings.ToLower(strings.TrimSpace(computer))}
	realm := strings.ToLower(strings.TrimSpace(fields[prefix+"DomainName"]))
	sid := strings.ToUpper(strings.TrimSpace(fields[prefix+"UserSid"]))
	name := fields[prefix+"UserName"]
	host := strings.Split(i.Computer, ".")[0]
	// Local, well-known, anonymous and machine principals are not domain users.
	if i.Computer != "" && accountSID.MatchString(sid) && realm != "" && realm != "-" && realm != "." && realm != "workgroup" && realm != "nt authority" && realm != "builtin" && realm != i.Computer && realm != host && name != "" && name != "-" && !strings.HasSuffix(name, "$") {
		valid := true
		for _, p := range strings.Split(sid, "-")[4:] {
			v, e := strconv.ParseUint(p, 10, 32)
			if e != nil || v == 0 {
				valid = false
			}
		}
		if valid {
			i.AccountSID = sid
			i.Realm = realm
			i.AccountKey = "windows-sid:" + sid
		}
	}
	if n, e := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(fields[prefix+"LogonId"]), "0x"), 16, 64); strings.HasPrefix(strings.ToLower(fields[prefix+"LogonId"]), "0x") && e == nil && n > 0 {
		i.LocalSession = "0x" + strconv.FormatUint(n, 16)
	}
	i.SessionGUID = WindowsGUID(fields["LogonGuid"])
	i.AccountRef = WindowsAccountRef(fields[prefix+"UserName"], fields[prefix+"DomainName"], computer)
	i.LogonType, _ = strconv.Atoi(fields["LogonType"])
	return i
}

func WindowsGUID(value string) string {
	guid := strings.ToLower(strings.Trim(value, "{}"))
	if len(guid) == 36 && guid[8] == '-' && guid[13] == '-' && guid[18] == '-' && guid[23] == '-' {
		raw := strings.ReplaceAll(guid, "-", "")
		if b, e := hex.DecodeString(raw); e == nil && len(b) == 16 {
			nonzero := false
			for _, v := range b {
				nonzero = nonzero || v != 0
			}
			if nonzero {
				return guid
			}
		}
	}
	return ""
}
func sshIdentity(fields func(string) string, msg string) *Identity {
	i := &Identity{Computer: fields("_HOSTNAME")}
	if m := sshFingerprint.FindStringSubmatch(msg); m != nil && strings.HasPrefix(msg, "Accepted publickey ") {
		if b, e := base64.RawStdEncoding.DecodeString(m[1]); e == nil && len(b) == 32 {
			i.SSHKey = "SHA256:" + m[1]
		}
	}
	boot := strings.ToLower(fields("_BOOT_ID"))
	pid, e := strconv.ParseUint(fields("_PID"), 10, 32)
	if b, err := hex.DecodeString(boot); err == nil && len(b) == 16 && e == nil && pid > 0 {
		i.LocalSession = "sshd:" + boot + ":" + strconv.FormatUint(pid, 10)
	}
	return i
}

// RemoteAddress rejects placeholders and local-only addresses for network-logon chains.
func RemoteAddress(s string) bool {
	ip, e := netip.ParseAddr(s)
	return e == nil && ip.Zone() == "" && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast()
}
