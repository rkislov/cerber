// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"errors"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/patch"
	"testing"
	"time"
)

func patchFixture(t *testing.T) (*Store, string, string, string) {
	s, id, hash := jobFixture(t)
	snap := inventory.Snapshot{SchemaVersion: 1, ID: "local", AssetID: "local", CollectedAt: time.Now().UTC(), Collector: "fixture", OS: inventory.OS{Family: "linux"}, PackageManager: "apt", Coverage: []inventory.Coverage{{Section: "updates_available", Status: "complete"}}, Updates: []inventory.Update{{ID: "debian:openssl:amd64", Title: "openssl", State: "available", Source: "apt-cache", InstalledVersion: "1.0", AvailableVersion: "1.1", Architecture: "amd64"}}}
	r, e := s.AcceptReport(context.Background(), id, hash, ingest.Report{SchemaVersion: 1, ID: "patch-report", AgentID: id, Snapshot: snap})
	if e != nil {
		t.Fatal(e)
	}
	return s, id, hash, r.SnapshotID
}
func TestPatchPreviewInstallOwnershipReplayAndAudit(t *testing.T) {
	ctx := context.Background()
	s, id, hash, inv := patchFixture(t)
	now := time.Now().UTC()
	c := patch.Command{Action: "preview", AgentID: id, InventoryID: inv, UpdateIDs: []string{"debian:openssl:amd64"}}
	j, e := s.PatchCommand(ctx, c, now)
	if e != nil {
		t.Fatal(e)
	}
	if j.Request.Validate() != nil {
		t.Fatal(j)
	}
	if _, e = s.PatchCommand(ctx, c, now); !errors.Is(e, patch.ErrConflict) {
		t.Fatal("active duplicate", e)
	}
	if _, e = s.ClaimPatch(ctx, id, "wrong", now); !errors.Is(e, ingest.ErrUnauthorized) {
		t.Fatal("auth", e)
	}
	q, e := s.ClaimPatch(ctx, id, hash, now)
	if e != nil || q == nil {
		t.Fatal(e)
	}
	again, e := s.ClaimPatch(ctx, id, hash, now)
	if e != nil || again.ID != q.ID {
		t.Fatal("claim must redeliver identical ID", e)
	}
	r := patch.Result{ID: q.ID, Status: "succeeded", Reboot: "unknown", Items: []patch.Item{{ID: c.UpdateIDs[0], Status: "ready", Code: "applicable"}}}
	if e = s.FinishPatch(ctx, id, hash, r, now); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishPatch(ctx, id, hash, r, now); e != nil {
		t.Fatal("ack retry", e)
	}
	r.Reboot = "yes"
	if e = s.FinishPatch(ctx, id, hash, r, now); !errors.Is(e, patch.ErrConflict) {
		t.Fatal("immutable result", e)
	}
	c.Action = "install"
	c.PreviewID = q.ID
	j, e = s.PatchCommand(ctx, c, now)
	if e != nil {
		t.Fatal(e)
	}
	q, e = s.ClaimPatch(ctx, id, hash, now)
	if e != nil {
		t.Fatal(e)
	}
	r = patch.Failure(*q, "interrupted")
	r.Status = "unknown"
	r.Items[0].Status = "unknown"
	if e = s.FinishPatch(ctx, id, hash, r, now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.PatchCommand(ctx, c, now); !errors.Is(e, patch.ErrConflict) {
		t.Fatal("preview reused after unknown", e)
	}
	items, e := s.PatchJobs(ctx, id)
	if e != nil || len(items) != 2 || items[0].State != "unknown" {
		t.Fatal(items, e)
	}
	events, _ := s.Events(ctx, 0, 1000)
	finishes := 0
	for _, event := range events {
		if event.Kind == "patch.finished" {
			finishes++
		}
	}
	if finishes != 2 {
		t.Fatal("duplicate finish audit", finishes)
	}
}
func TestPatchRBACStalenessSelectionAndAtomicAudit(t *testing.T) {
	ctx := context.Background()
	s, id, _, inv := patchFixture(t)
	now := time.Now().UTC()
	c := patch.Command{Action: "preview", AgentID: id, InventoryID: inv, UpdateIDs: []string{"debian:openssl:amd64"}}
	hash, _ := admin.HashPassword("fixture-password-123")
	if e := s.AdminCommand(ctx, admin.Command{Action: "user.create", Username: "root", Role: "administrator", PasswordHash: hash}); e != nil {
		t.Fatal(e)
	}
	for _, role := range []string{"operator", "analyst", "viewer"} {
		if e := s.AdminCommand(ctx, admin.Command{Action: "user.create", Username: role, Role: role, PasswordHash: hash}); e != nil {
			t.Fatal(e)
		}
		u, _ := s.AdminUser(ctx, role)
		if _, e := s.PatchCommand(admin.WithPrincipal(ctx, u), c, now); !errors.Is(e, admin.ErrForbidden) {
			t.Fatal(role, e)
		}
	}
	bad := c
	bad.UpdateIDs = []string{"missing"}
	if _, e := s.PatchCommand(ctx, bad, now); !errors.Is(e, patch.ErrInvalid) {
		t.Fatal(e)
	}
	if _, e := s.PatchCommand(ctx, c, now.Add(25*time.Hour)); !errors.Is(e, patch.ErrConflict) {
		t.Fatal("stale inventory", e)
	}
	bad = c
	bad.InventoryID = "old"
	if _, e := s.PatchCommand(ctx, bad, now); !errors.Is(e, patch.ErrConflict) {
		t.Fatal(e)
	}
	if _, e := s.db.Exec(`CREATE TRIGGER fail_patch_audit BEFORE INSERT ON outbox WHEN NEW.kind='patch.queued' BEGIN SELECT RAISE(FAIL,'fixture'); END;`); e != nil {
		t.Fatal(e)
	}
	if _, e := s.PatchCommand(ctx, c, now); e == nil {
		t.Fatal("missing audit rollback")
	}
	items, _ := s.PatchJobs(ctx, id)
	if len(items) != 0 {
		t.Fatal(items)
	}
}
