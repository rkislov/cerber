package telemetry

import "testing"

func TestActivityKeepsActorSeparate(t *testing.T) {
	for _, code := range []int{4688, 4697, 4698} {
		n := flowNormalize(t, code, map[string]string{"SubjectUserName": "Alice", "SubjectDomainName": "LAB", "SubjectUserSid": "S-1-5-21-1-2-3-1001", "SubjectLogonId": "0x123", "ServiceAccount": "SYSTEM", "NewProcessName": "test.exe", "TargetUserSid": "S-1-5-18"})
		if n.WindowsActivity == nil || n.Identity.AccountSID != "S-1-5-21-1-2-3-1001" || n.Identity.LocalSession != "0x123" {
			t.Fatal(code, n)
		}
	}
	n := Normalized{}
	normalizeWindowsActivity(&n, map[string]string{"AccountName": "SYSTEM", "ServiceName": "test", "ImagePath": "test.exe"}, "host", 7045)
	if n.User != "" || n.Identity.AccountSID != "" || n.Identity.LocalSession != "" || n.WindowsActivity.RunAs != "SYSTEM" {
		t.Fatal("7045 invented actor", n)
	}
}
