// SPDX-License-Identifier: Apache-2.0
package vuln

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rkislov/cerber/internal/inventory"
)

func microsoftFixture(t *testing.T) (*Catalog, inventory.Snapshot) {
	t.Helper()
	c, e := Open(filepath.Join(t.TempDir(), "catalog.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	now := time.Now().UTC()
	id := now.Format("2006-Jan")
	meta := microsoftDocument{ID: id, At: now, Modified: now, Attempt: now, SHA256: strings.Repeat("a", 64), Records: 3}
	p, _ := json.Marshal(meta)
	if _, e = c.db.Exec("INSERT INTO msrc_documents VALUES(?,?)", id, string(p)); e != nil {
		t.Fatal(e)
	}
	c.saveMicrosoftState(context.Background(), MicrosoftStatus{At: now, Attempt: now, Expected: 1, Releases: []microsoftRelease{{ID: id, InitialReleaseDate: now.Format(time.RFC3339), CurrentReleaseDate: now.Format(time.RFC3339)}}})
	items := []microsoftEntry{
		{CVE: "CVE-2025-12345", Title: "Fixture Windows issue", Target: "windows_11_23h2|x64|client", ProductID: "12243", Product: "Windows 11 Version 23H2 for x64-based Systems", KB: "KB5000001", FixedBuild: "10.0.22631.1000", Score: 8.1, Severity: "high"},
		{CVE: "CVE-2025-12346", Target: "windows_11_23h2|x64|client", ProductID: "12243", KB: "KB5000002", FixedBuild: "10.0.22631.1100", Supersedes: []string{"KB5000001"}},
		{CVE: "CVE-2025-12347", Target: "windows_11_23h2|arm64|client", ProductID: "12242", KB: "KB5000003", Supersedes: []string{"KB5000001"}},
	}
	for n, v := range items {
		p, _ := json.Marshal(v)
		if _, e = c.db.Exec("INSERT INTO msrc_entries VALUES(?,?,?,?,?)", id, n, v.CVE, v.Target, string(p)); e != nil {
			t.Fatal(e)
		}
	}
	no := false
	s := inventory.Snapshot{ID: "fixture", CollectedAt: now, OS: inventory.OS{Family: "windows", Name: "Microsoft Windows 11 Pro", Version: "10.0.22631", Build: "22631.900", Edition: "Professional", Architecture: "x64", Release: "23H2", RebootRequired: &no}, Coverage: []inventory.Coverage{{Section: "os", Status: "complete"}, {Section: "updates_installed", Status: "partial"}}}
	return c, s
}
func microsoftAssessment(t *testing.T, c *Catalog, s inventory.Snapshot) WindowsFinding {
	t.Helper()
	r, e := c.windowsInventory(context.Background(), s, 0, 50, "CVE-2025-12345")
	if e != nil || len(r.Items) != 1 {
		t.Fatal(r, e)
	}
	return r.Items[0]
}
func TestMicrosoftBuildAndPartialKBInventory(t *testing.T) {
	c, s := microsoftFixture(t)
	if a := microsoftAssessment(t, c, s); a.Assessment.Status != "affected" {
		t.Fatal(a)
	}
	s.OS.Build = "22631.1000"
	if a := microsoftAssessment(t, c, s); a.Assessment.Status != "fixed" {
		t.Fatal(a)
	}
	yes := true
	s.OS.RebootRequired = &yes
	if a := microsoftAssessment(t, c, s); a.Assessment.Status != "unknown" {
		t.Fatal("pending reboot hidden", a)
	}
	s.OS.RebootRequired = nil
	if a := microsoftAssessment(t, c, s); a.Assessment.Status != "unknown" {
		t.Fatal("old agent missing reboot state", a)
	}
	s.OS.Build = "22631.900"
	s.Updates = []inventory.Update{{State: "installed", Source: "windows-update-agent-local-cache", KBs: []string{"5000001"}}}
	if a := microsoftAssessment(t, c, s); a.Assessment.Status != "unknown" || a.Windows.InstalledKB != "KB5000001" {
		t.Fatal("installed/build contradiction", a)
	}
}
func TestMicrosoftReplacementDirectionAndProductIsolation(t *testing.T) {
	c, s := microsoftFixture(t)
	s.Updates = []inventory.Update{{State: "installed", Source: "windows-update-agent-local-cache", KBs: []string{"KB5000002"}}}
	a := microsoftAssessment(t, c, s)
	if a.Assessment.Status != "unknown" || len(a.Windows.Supersedence) != 2 || a.Windows.Supersedence[0] != "KB5000002" {
		t.Fatal(a)
	}
	s.Updates[0].KBs = []string{"KB5000003"}
	a = microsoftAssessment(t, c, s)
	if a.Assessment.Status != "affected" || a.Windows.InstalledKB != "" {
		t.Fatal("other architecture replacement used", a)
	}
	s.Updates[0].KBs = []string{"KB9999999"}
	if a = microsoftAssessment(t, c, s); a.Windows.InstalledKB != "" {
		t.Fatal("numeric KB ordering inferred replacement", a)
	}
	// An older KB does not satisfy the update that replaces it.
	s.Updates[0].KBs = []string{"KB5000001"}
	r, e := c.windowsInventory(context.Background(), s, 0, 1, "CVE-2025-12346")
	if e != nil || r.Items[0].Assessment.Status != "affected" || r.Items[0].Windows.InstalledKB != "" {
		t.Fatal(r, e)
	}
}
func TestMicrosoftIdentityFreshnessAndUnknownRemediation(t *testing.T) {
	c, s := microsoftFixture(t)
	ctx := context.Background()
	for _, alter := range []func(*inventory.Snapshot){func(s *inventory.Snapshot) { s.OS.Release = "24H2" }, func(s *inventory.Snapshot) { s.OS.Edition = "IoTEnterprise" }, func(s *inventory.Snapshot) { s.OS.Build = "22631" }, func(s *inventory.Snapshot) { s.OS.Version = "10.0.26100" }} {
		bad := s
		alter(&bad)
		r, e := c.WindowsInventory(ctx, bad, 0, 50)
		if e != nil || r.Status != "unknown" || len(r.Items) != 0 {
			t.Fatal(r, e)
		}
	}
	stale := s
	stale.CollectedAt = time.Now().Add(-25 * time.Hour)
	if a := microsoftAssessment(t, c, stale); a.Assessment.Status != "unknown" {
		t.Fatal(a)
	}
	c.db.Exec("UPDATE msrc_entries SET payload=json_set(payload,'$.FixedBuild','') WHERE cve='CVE-2025-12345'")
	if a := microsoftAssessment(t, c, s); a.Assessment.Status != "unknown" {
		t.Fatal("absent KB treated as vulnerable", a)
	}
	c.db.Exec("UPDATE msrc_documents SET payload=json_set(payload,'$.error','network failure')")
	if a := microsoftAssessment(t, c, s); a.Assessment.Status != "unknown" || !strings.Contains(a.Assessment.Reason, "MSRC") {
		t.Fatal(a)
	}
}
func TestMicrosoftServerCoreAndSharedClientBuild(t *testing.T) {
	no := false
	s := inventory.Snapshot{OS: inventory.OS{Family: "windows", Name: "Microsoft Windows Server 2025 Standard", Edition: "ServerStandard", Architecture: "x64", Version: "10.0.26100", Build: "26100.1000", RebootRequired: &no}}
	if key, _ := snapshotWindowsTarget(s); key != "" {
		t.Fatal("missing installation type matched", key)
	}
	s.OS.InstallationType = "Server Core"
	if key, _ := snapshotWindowsTarget(s); key != "windows_server_2025|x64|core" {
		t.Fatal(key)
	}
	s.OS.InstallationType = "Server"
	if key, _ := snapshotWindowsTarget(s); key != "windows_server_2025|x64|server" {
		t.Fatal(key)
	}
}
func microsoftRawFixture() []byte {
	now := time.Now().UTC()
	doc := map[string]any{
		"DocumentTracking": map[string]any{"Identification": map[string]any{"ID": map[string]string{"Value": now.Format("2006-Jan")}}, "CurrentReleaseDate": now.Format(time.RFC3339)},
		"ProductTree":      map[string]any{"FullProductName": []map[string]string{{"ProductID": "12243", "Value": "Windows 11 Version 23H2 for x64-based Systems", "CPE": "cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:x64:*"}}},
		"Vulnerability":    []any{map[string]any{"CVE": "CVE-2025-12345", "Title": map[string]string{"Value": "Fixture"}, "ProductStatuses": []any{map[string]any{"Type": 3, "ProductID": []string{"12243"}}}, "CVSSScoreSets": []any{map[string]any{"BaseScore": 9.1, "ProductID": []string{"12243"}}}, "Remediations": []any{map[string]any{"Type": 2, "ProductID": []string{"12243"}, "Description": map[string]string{"Value": "5000001"}, "FixedBuild": "10.0.22631.1000", "Supercedence": "5000000"}}}},
	}
	p, _ := json.Marshal(doc)
	return p
}

type microsoftTransport func(*http.Request) (*http.Response, error)

func (f microsoftTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestMicrosoftSyncPersistsIndexAndRetainsDataOnFailure(t *testing.T) {
	c, e := Open(filepath.Join(t.TempDir(), "catalog.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	old := microsoftClient
	t.Cleanup(func() { microsoftClient = old })
	calls := 0
	bad := false
	now := time.Now().UTC()
	id := now.Format("2006-Jan")
	microsoftClient = &http.Client{Transport: microsoftTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "api.msrc.microsoft.com" {
			t.Fatal(r.URL)
		}
		data := microsoftRawFixture()
		if strings.HasSuffix(r.URL.Path, "updates") {
			data, _ = json.Marshal(map[string]any{"value": []microsoftRelease{{ID: id, CurrentReleaseDate: now.Format(time.RFC3339), InitialReleaseDate: now.Format(time.RFC3339)}}})
		} else if bad {
			data = []byte(`{"broken":true}`)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: make(http.Header)}, nil
	})}
	ctx := context.Background()
	c.SyncMicrosoft(ctx)
	status := c.MicrosoftStatus(ctx)
	if status.Documents != 1 || status.Records != 1 || !status.InitialComplete {
		t.Fatal(status)
	}
	if len(c.microsoftState(ctx).Releases) != 1 {
		t.Fatal("release index not persisted")
	}
	c.SyncMicrosoft(ctx)
	if calls != 2 {
		t.Fatal("fetched unchanged feed", calls)
	}
	bad = true
	c.RequestMicrosoft()
	c.SyncMicrosoft(ctx)
	status = c.MicrosoftStatus(ctx)
	if status.Records != 1 || status.Errors != 1 || status.InitialComplete {
		t.Fatal("failed refresh destroyed data", status)
	}
}
func TestParseMicrosoftRejectsImpostorIdentity(t *testing.T) {
	data := microsoftRawFixture()
	if _, entries, e := parseMicrosoft(data, time.Now().Format("2006-Jan")); e != nil || len(entries) != 1 || entries[0].FixedBuild != "10.0.22631.1000" {
		t.Fatal(entries, e)
	}
	if _, _, e := parseMicrosoft(data, "2020-Jan"); e == nil {
		t.Fatal("wrong source identity accepted")
	}
	var v map[string]any
	json.Unmarshal(data, &v)
	v["ProductTree"] = map[string]any{"FullProductName": []map[string]string{{"ProductID": "12243", "Value": "Windows 11 Version 23H2 for x64-based Systems", "CPE": "cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*"}}}
	p, _ := json.Marshal(v)
	if _, entries, e := parseMicrosoft(p, time.Now().Format("2006-Jan")); e != nil || len(entries) != 0 {
		t.Fatal(entries, e)
	}
}

func TestMicrosoftCompressedChunksAndHostileCPE(t *testing.T) {
	items := []microsoftEntry{{CVE: "CVE-2025-12345", Title: "Fixture", Target: "windows_11_23h2|x64|client"}}
	data, e := encodeMicrosoftEntries(items)
	if e != nil {
		t.Fatal(e)
	}
	out, e := decodeMicrosoftEntries(data)
	if e != nil || len(out) != 1 || out[0].CVE != items[0].CVE {
		t.Fatal(out, e)
	}
	data[len(data)-1] ^= 255
	if _, e = decodeMicrosoftEntries(data); e == nil {
		t.Fatal("corrupt compressed cache accepted")
	}
	p := microsoftProduct{Value: "Windows 11 Version 23H2 for x64-based Systems", CPE: "cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:arm64:*"}
	if productTarget(p) != "" {
		t.Fatal("contradictory architecture accepted")
	}
}
