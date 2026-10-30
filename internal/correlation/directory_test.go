// SPDX-License-Identifier: Apache-2.0
package correlation

import (
	"github.com/rkislov/cerber/internal/telemetry"
	"testing"
	"time"
)

func TestDirectoryVerifiedAliasRequiresSameSIDGUIDAndDomain(t *testing.T) {
	proof := telemetry.DirectoryProof{State: "verified", SID: "S-1-5-21-1-2-3-1001", DomainSID: "S-1-5-21-1-2-3", GUID: "1234567890123456"}
	w := &telemetry.WindowsAuth{AccountRef: `lab.example\alice`, Directory: &proof}
	i := &telemetry.Identity{AccountRef: `lab\alice`, Directory: &proof}
	if !flowAccountMatch(w, i) {
		t.Fatal("verified DNS/NetBIOS rejected")
	}
	for _, field := range []string{"sid", "guid", "domain", "state"} {
		p := proof
		switch field {
		case "sid":
			p.SID = "other"
		case "guid":
			p.GUID = "recreated-account"
		case "domain":
			p.DomainSID = "other-domain"
		case "state":
			p.State = "disabled"
		}
		w.Directory = &p
		if flowAccountMatch(w, i) {
			t.Fatal("false merge", field)
		}
	}
	w.Directory = nil
	if flowAccountMatch(w, i) {
		t.Fatal("unverified alias merged")
	}
	w.AccountRef = i.AccountRef
	if !flowAccountMatch(w, i) {
		t.Fatal("exact source matching regressed")
	}
	w.Directory = &telemetry.DirectoryProof{State: "sid_mismatch"}
	if flowAccountMatch(w, i) {
		t.Fatal("known mismatch ignored")
	}
}
func TestDirectoryDoesNotReplaceGUIDOrderOrHostRequirements(t *testing.T) {
	proof := &telemetry.DirectoryProof{State: "verified", SID: "S-1-5-21-1-2-3-1001", DomainSID: "S-1-5-21-1-2-3", GUID: "1234567890123456"}
	now := time.Now()
	n := telemetry.Normalized{ID: "target", AgentID: "files", AssetID: "target", Status: "parsed", Class: "authentication", Action: "logon", Outcome: "success", Sequence: 3, EventTime: now, SourceIP: "192.0.2.5", Identity: &telemetry.Identity{AccountKey: "windows-sid:" + proof.SID, AccountRef: `lab\alice`, SessionGUID: "guid", LogonType: 3, Directory: proof}}
	p := telemetry.Normalized{ID: "ticket", AgentID: "dc", AssetID: "dc", Status: "parsed", Class: "kerberos", Action: "kerberos_service_ticket", Outcome: "success", Sequence: 2, EventTime: now.Add(-time.Minute), Identity: &telemetry.Identity{SessionGUID: "guid"}, WindowsAuth: &telemetry.WindowsAuth{AccountRef: `lab.example\alice`, Directory: proof}}
	if !TicketMatches(p, n) {
		t.Fatal("verified ticket rejected")
	}
	p.Identity.SessionGUID = "other"
	if TicketMatches(p, n) {
		t.Fatal("directory replaced GUID")
	}
	p.Identity.SessionGUID = "guid"
	p.AgentID = n.AgentID
	if TicketMatches(p, n) {
		t.Fatal("same host accepted")
	}
	p.AgentID = "dc"
	p.Sequence = 4
	if TicketMatches(p, n) {
		t.Fatal("future ingestion accepted")
	}
}
