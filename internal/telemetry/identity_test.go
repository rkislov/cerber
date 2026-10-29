// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSourceIdentityScopeAndZeroGUID(t *testing.T) {
	f := map[string]string{"TargetUserName": "Alice", "TargetDomainName": "LAB", "TargetUserSid": "S-1-5-21-111-222-333-1001", "TargetLogonId": "0x00ABC", "LogonGuid": "{11111111-2222-3333-4444-555555555555}", "LogonType": "3"}
	i := windowsIdentity(f, "node1.lab", "Target")
	if i.AccountKey == "" || i.LocalSession != "0xabc" || i.SessionGUID == "" {
		t.Fatal(i)
	}
	for _, domain := range []string{"node1", "NODE1.LAB", "WORKGROUP", "NT AUTHORITY", ".", "-", ""} {
		f["TargetDomainName"] = domain
		if windowsIdentity(f, "node1.lab", "Target").AccountKey != "" {
			t.Fatal("local account joined", domain)
		}
	}
	f["TargetDomainName"] = "LAB"
	for _, sid := range []string{"S-1-5-18", "S-1-0-0", "S-1-5-21-1-2-3-9999999999999999", "S-1-5-21-1-0-3-1000"} {
		f["TargetUserSid"] = sid
		if windowsIdentity(f, "node1.lab", "Target").AccountKey != "" {
			t.Fatal(sid)
		}
	}
	f["LogonGuid"] = "{00000000-0000-0000-0000-000000000000}"
	f["TargetLogonId"] = "0x0"
	if i = windowsIdentity(f, "node1", "Target"); i.SessionGUID != "" || i.LocalSession != "" {
		t.Fatal(i)
	}
	f["TargetUserSid"] = "S-1-5-21-1-2-3-1000"
	f["TargetUserName"] = "node$"
	if windowsIdentity(f, "node1", "Target").AccountKey != "" {
		t.Fatal("machine principal")
	}
}
func TestSSHKeyIdentityRequiresTrustedCollectorFields(t *testing.T) {
	at := time.Now().UTC()
	m := map[string]string{"_UID": "0", "_EXE": "/usr/sbin/sshd", "_PID": "42", "_BOOT_ID": strings.Repeat("a", 32), "__REALTIME_TIMESTAMP": "1700000000000000", "MESSAGE": "Accepted publickey for root from 192.0.2.2 port 1234 ssh2: ED25519 SHA256:" + strings.Repeat("A", 43)}
	normalize := func() Normalized {
		p, _ := json.Marshal(m)
		return Normalize(RawRecord{ReceivedAt: at, Raw: Raw{Source: "journald", ObservedAt: at, Data: p}})
	}
	n := normalize()
	if n.Identity == nil || n.Identity.SSHKey == "" || n.Identity.LocalSession == "" {
		t.Fatal(n)
	}
	m["_UID"] = "1000"
	if n = normalize(); n.Identity != nil {
		t.Fatal("untrusted log became key identity")
	}
	m["_UID"] = "0"
	m["MESSAGE"] = "Accepted password for root from 192.0.2.2 port 1234 ssh2"
	if n = normalize(); n.Identity.SSHKey != "" {
		t.Fatal(n)
	}
}

func TestWindowsGUIDRejectsAdditionalHyphens(t *testing.T) {
	fields := map[string]string{"LogonGuid": "11111111-2222-3333-4444-55--55555555"}
	if got := windowsIdentity(fields, "node1", "Target").SessionGUID; got != "" {
		t.Fatal("malformed GUID accepted", got)
	}
}
