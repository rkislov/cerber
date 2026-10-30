// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"errors"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/ingest"
	"path/filepath"
	"testing"
)

func TestAccountPersistenceAndAtomicAgentAudit(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "siem.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := admin.HashPassword("fixture-long-password")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AdminCommand(ctx, admin.Command{Action: "user.create", Username: "reader", Role: "viewer", PasswordHash: hash}); !errors.Is(err, admin.ErrInvalid) {
		t.Fatal("first user must administer", err)
	}
	if err = s.AdminCommand(ctx, admin.Command{Action: "user.create", Username: "root", Role: "administrator", PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	root, err := s.AdminUser(ctx, "root")
	if err != nil || !admin.CheckPassword(root.PasswordHash, "fixture-long-password") {
		t.Fatal("account persistence", err)
	}
	principal := admin.WithPrincipal(ctx, root)
	if err = s.AdminCommand(principal, admin.Command{Action: "user.update", Username: "root", Role: "administrator", Disabled: true}); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("last admin disabled", err)
	}
	if _, err = s.db.Exec(`CREATE TRIGGER fail_audit BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.AdminCommand(principal, admin.Command{Action: "user.update", Username: "root", Role: "administrator", PasswordHash: hash}); err == nil {
		t.Fatal("audit failure accepted user change")
	}
	unchanged, err := s.AdminUser(ctx, "root")
	if err != nil || unchanged.Version != root.Version {
		t.Fatal("user version did not roll back", err)
	}
	c := admin.Command{Action: "agent.enroll", AgentID: "fixture-agent", AssetID: "fixture-asset", Name: "fixture", IP: "192.0.2.99", TokenHash: ingest.Hash([]byte("fixture"))}
	if err = s.AdminCommand(principal, c); err == nil {
		t.Fatal("audit failure must reject operation")
	}
	var assets, agents int
	s.db.QueryRow("SELECT count(*) FROM assets").Scan(&assets)
	s.db.QueryRow("SELECT count(*) FROM agents").Scan(&agents)
	if assets != 0 || agents != 0 {
		t.Fatal("partial mutation", assets, agents)
	}
	if _, err = s.db.Exec("DROP TRIGGER fail_audit"); err != nil {
		t.Fatal(err)
	}
	if err = s.AdminCommand(principal, c); err != nil {
		t.Fatal(err)
	}
	if err = s.AdminCommand(principal, admin.Command{Action: "agent.enroll", AgentID: "second-agent", AssetID: "fixture-asset", TokenHash: c.TokenHash}); err != nil {
		t.Fatal("existing asset enrollment", err)
	}
	if err = s.AdminCommand(principal, admin.Command{Action: "agent.enroll", AgentID: "invalid-agent", AssetID: "missing-asset", TokenHash: c.TokenHash}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("missing asset", err)
	}
	if _, err = s.db.Exec(`CREATE TRIGGER fail_audit BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.AdminCommand(principal, admin.Command{Action: "agent.revoke", AgentID: c.AgentID}); err == nil {
		t.Fatal("audit failure accepted revoke")
	}
	if _, err = s.AgentBinding(ctx, c.AgentID, c.TokenHash); err != nil {
		t.Fatal("revoke did not roll back", err)
	}
}

func TestVersionSixAccountMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "siem.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO assets VALUES('asset','192.0.2.5','fixture','2026-01-01T00:00:00.000000000Z'); DROP TABLE admin_users; PRAGMA user_version=6;`); err != nil {
		t.Fatal(err)
	}
	if err = s.RegisterAgent(ctx, "old-agent", "asset", ingest.Hash([]byte("old-token"))); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.AgentBinding(ctx, "old-agent", ingest.Hash([]byte("old-token"))); err != nil {
		t.Fatal("old agent lost", err)
	}
	if n, err := s.AdminUserCount(ctx); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	var version int
	if err = s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 15 {
		t.Fatal(version, err)
	}
}

func TestAnalystCannotMutateInfrastructure(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	hash, e := admin.HashPassword("fixture-only-password")
	if e != nil {
		t.Fatal(e)
	}
	for _, u := range []admin.User{{Username: "root", Role: "administrator"}, {Username: "analyst", Role: "analyst"}} {
		if e = s.AdminCommand(ctx, admin.Command{Action: "user.create", Username: u.Username, Role: u.Role, PasswordHash: hash}); e != nil {
			t.Fatal(e)
		}
	}
	u, e := s.AdminUser(ctx, "analyst")
	if e != nil {
		t.Fatal(e)
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = checkAdmin(admin.WithPrincipal(ctx, u), tx, false); !errors.Is(e, admin.ErrForbidden) {
		t.Fatal("analyst inherited operator permissions", e)
	}
}
