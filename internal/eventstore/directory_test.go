// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/directory"
	"github.com/rkislov/cerber/internal/rulepolicy"
	"github.com/rkislov/cerber/internal/telemetry"
	"strings"
	"testing"
	"time"
)

type fixtureDirectory struct {
	s        *Store
	t        *testing.T
	prepared int
	queries  []directory.Query
}

func (f *fixtureDirectory) Enabled() bool { return true }
func (f *fixtureDirectory) Prepare(ctx context.Context, q []directory.Query) {
	f.prepared++
	f.queries = append(f.queries, q...)
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if e := f.s.db.PingContext(ctx); e != nil {
		f.t.Fatal("LDAPS preflight holds a SQLite transaction", e)
	}
}
func (f *fixtureDirectory) Attest(n telemetry.Normalized) telemetry.Normalized {
	proof := func(name string) *telemetry.DirectoryProof {
		sid := "S-1-5-21-111-222-333-1002"
		guid := "22222222-2222-2222-2222-222222222222"
		if strings.Contains(strings.ToLower(name), "alice") {
			sid = chainSID
			guid = "11111111-1111-1111-1111-111111111111"
		}
		return &telemetry.DirectoryProof{State: "verified", SID: sid, GUID: guid, DomainSID: "S-1-5-21-111-222-333", DNS: "lab.example", NetBIOS: "lab", CheckedAt: time.Now().UTC(), ValidUntil: time.Now().Add(time.Minute).UTC()}
	}
	if n.Identity != nil {
		v := *n.Identity
		n.Identity = &v
		if v.AccountRef != "" {
			v.Directory = proof(v.AccountRef)
		}
	}
	if n.WindowsAuth != nil {
		v := *n.WindowsAuth
		n.WindowsAuth = &v
		v.Directory = proof(v.TargetAccount)
	}
	return n
}
func TestDirectoryAliasLivePreviewAndImmutableEvidence(t *testing.T) {
	s := storageFixture(t)
	ctx := context.Background()
	f := &fixtureDirectory{s: s, t: t}
	s.SetDirectory(f)
	at := time.Now().UTC().Add(-5 * time.Minute)
	chainEvent(t, s, "workstation", "source", at, 4624, actorFields())
	fields := explicitFields()
	fields["TargetDomainName"] = "lab.example"
	chainEvent(t, s, "workstation", "source", at.Add(time.Minute), 4648, fields)
	fields = ticketFields()
	fields["TargetUserName"] = "Bob@lab.example"
	fields["TargetDomainName"] = "LAB"
	chainEvent(t, s, "dc", "dc-asset", at.Add(2*time.Minute), 4769, fields)
	last := chainEvent(t, s, "files", "files-asset", at.Add(3*time.Minute), 4624, targetFields())
	ds, e := s.ReadDetections(ctx, 0, 100)
	if e != nil || len(ds) != 2 {
		t.Fatal("AD aliases did not join live flow", len(ds), e)
	}
	for _, d := range ds {
		if len(d.Chain.Steps) != 4 || !strings.Contains(d.Chain.Links[1].Basis, "AD/LDAPS") {
			t.Fatal("proof missing", d.Chain)
		}
		if d.Chain.Steps[2].Identity.AccountSID != "" || d.Chain.Steps[2].WindowsAuth.Directory.SID != "S-1-5-21-111-222-333-1002" {
			t.Fatal("ticket user SID confused with service or actor")
		}
	}
	var stored string
	if e = s.db.QueryRowContext(ctx, "SELECT payload FROM normalized_events WHERE id=?", last).Scan(&stored); e != nil {
		t.Fatal(e)
	}
	var n telemetry.Normalized
	json.Unmarshal([]byte(stored), &n)
	if n.Identity.Directory != nil {
		t.Fatal("source row mutated")
	}
	p, e := s.PreviewRule(ctx, RulePreviewRequest{Rule: "chain.kerberos_logon", Config: rulepolicy.Defaults()["chain.kerberos_logon"], EventIDs: []string{last}}, nil, "")
	if e != nil || len(p.Rows) != 1 || len(p.Rows[0].Findings) != 1 {
		t.Fatal("preview differs", p, e)
	}
	after, _ := s.ReadDetections(ctx, 0, 100)
	if len(after) != 2 {
		t.Fatal("preview created detections")
	}
	if f.prepared < 5 {
		t.Fatal("preview did not prepare directory")
	}
	found := false
	for _, q := range f.queries {
		found = found || q.ImplicitUPN && q.Name == "Bob@lab.example" && q.Realm == "LAB"
	}
	if !found {
		t.Fatal("4769 implicit UPN fields lost")
	}
}
