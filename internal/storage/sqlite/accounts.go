// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/event"
	"github.com/rkislov/cerber/internal/ingest"
	"net/netip"
	"strings"
	"time"
)

func adminUser(ctx context.Context, q rowQuerier, name string) (admin.User, error) {
	var u admin.User
	err := q.QueryRowContext(ctx, `SELECT username,role,disabled,version,password_hash FROM admin_users WHERE username=?`, name).Scan(&u.Username, &u.Role, &u.Disabled, &u.Version, &u.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		err = domain.ErrNotFound
	}
	return u, err
}
func (s *Store) AdminUser(ctx context.Context, name string) (admin.User, error) {
	return adminUser(ctx, s.db, name)
}
func (s *Store) AdminUserCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM admin_users").Scan(&n)
	return n, err
}
func (s *Store) AdminUsers(ctx context.Context, after string, limit int) ([]admin.User, error) {
	if limit < 1 || limit > 101 {
		return nil, admin.ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, `SELECT username,role,disabled FROM admin_users WHERE username>? ORDER BY username LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := []admin.User{}
	for rows.Next() {
		var u admin.User
		if err = rows.Scan(&u.Username, &u.Role, &u.Disabled); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// Authorization is checked inside the same write transaction as the action.
// An absent principal is reserved for trusted local CLI calls.
func checkAdmin(ctx context.Context, tx *sql.Tx, accounts bool) error {
	u, ok := admin.Principal(ctx)
	if !ok {
		return nil
	}
	if u.Username == "" {
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM admin_users").Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			return admin.ErrForbidden
		}
		return nil
	}
	current, err := adminUser(ctx, tx, u.Username)
	if err != nil {
		return admin.ErrForbidden
	}
	if current.Disabled || current.Version != u.Version || (current.Role != "administrator" && current.Role != "operator") || accounts && current.Role != "administrator" {
		return admin.ErrForbidden
	}
	return nil
}
func (s *Store) AdminCommand(ctx context.Context, c admin.Command) error {
	accounts := c.Action == "user.create" || c.Action == "user.update"
	if !accounts && c.Action != "agent.enroll" && c.Action != "agent.revoke" {
		return admin.ErrInvalid
	}
	if accounts && (!admin.ValidUsername(c.Username) || !admin.ValidRole(c.Role)) {
		return admin.ErrInvalid
	}
	if c.Action == "user.create" && c.PasswordHash == "" {
		return admin.ErrInvalid
	}
	if c.Action == "agent.enroll" {
		if !ingest.Identifier(c.AgentID) || !ingest.Identifier(c.AssetID) || len(c.TokenHash) != 64 {
			return admin.ErrInvalid
		}
		if c.IP != "" {
			if _, err := netip.ParseAddr(c.IP); err != nil || len(strings.TrimSpace(c.Name)) == 0 || len(c.Name) > 256 {
				return admin.ErrInvalid
			}
		}
	}
	if c.Action == "agent.revoke" && !ingest.Identifier(c.AgentID) {
		return admin.ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = checkAdmin(ctx, tx, accounts); err != nil {
		return err
	}
	actor := "cli"
	if u, ok := admin.Principal(ctx); ok {
		actor = u.Username
		if actor == "" {
			actor = "legacy-administrator"
		}
	}
	switch c.Action {
	case "user.create":
		var n int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM admin_users WHERE username=?", c.Username).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			return domain.ErrConflict
		}
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM admin_users").Scan(&count); err != nil {
			return err
		}
		if count == 0 && (c.Role != "administrator" || c.Disabled) {
			return admin.ErrInvalid
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO admin_users(username,role,disabled,password_hash) VALUES(?,?,?,?)", c.Username, c.Role, c.Disabled, c.PasswordHash)
	case "user.update":
		old, e := adminUser(ctx, tx, c.Username)
		if e != nil {
			return e
		}
		if old.Role == "administrator" && !old.Disabled && (c.Role != "administrator" || c.Disabled) {
			var n int
			if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM admin_users WHERE role='administrator' AND disabled=0").Scan(&n); e != nil {
				return e
			}
			if n <= 1 {
				return domain.ErrConflict
			}
		}
		hash := old.PasswordHash
		if c.PasswordHash != "" {
			hash = c.PasswordHash
		}
		_, err = tx.ExecContext(ctx, "UPDATE admin_users SET role=?,disabled=?,password_hash=?,version=version+1 WHERE username=?", c.Role, c.Disabled, hash, c.Username)
	case "agent.enroll":
		if c.IP == "" {
			var n int
			if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM assets WHERE id=?", c.AssetID).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				return domain.ErrNotFound
			}
		}
		if c.IP != "" {
			var n int
			if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM assets WHERE ip=?", c.IP).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				return domain.ErrConflict
			}
		}
		if c.IP != "" {
			if _, err = tx.ExecContext(ctx, "INSERT INTO assets(id,ip,name,created_at) VALUES(?,?,?,?)", c.AssetID, c.IP, c.Name, stamp(time.Now())); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO agents(id,asset_id,token_hash,created_at) VALUES(?,?,?,?)", c.AgentID, c.AssetID, c.TokenHash, stamp(time.Now()))
	case "agent.revoke":
		var res sql.Result
		res, err = tx.ExecContext(ctx, "UPDATE agents SET revoked=1 WHERE id=? AND revoked=0", c.AgentID)
		if err == nil {
			n, _ := res.RowsAffected()
			if n == 0 {
				return domain.ErrNotFound
			}
		}
	}
	if err != nil {
		return err
	}
	kind, aggregate := "admin."+c.Action, c.Username
	if c.Action == "agent.enroll" {
		kind, aggregate = "agent.enrolled", c.AssetID
	}
	if c.Action == "agent.revoke" {
		kind, aggregate = "agent.revoked", c.AgentID
	}
	e, err := event.New(kind, aggregate, map[string]any{"actor": actor, "username": c.Username, "role": c.Role, "disabled": c.Disabled, "agent_id": c.AgentID, "asset_id": c.AssetID, "password_changed": c.PasswordHash != ""})
	if err != nil {
		return err
	}
	if err = appendEvent(ctx, tx, e); err != nil {
		return err
	}
	return tx.Commit()
}

// Record successful authentication without credentials or password hashes.
func (s *Store) AdminLogin(ctx context.Context, u admin.User) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	actor := u.Username
	if actor == "" {
		var n int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM admin_users").Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			return admin.ErrForbidden
		}
		actor = "legacy-administrator"
	} else {
		current, e := adminUser(ctx, tx, actor)
		if e != nil || current.Disabled || current.Version != u.Version {
			return admin.ErrForbidden
		}
	}
	e, err := event.New("admin.session.login", actor, map[string]string{"actor": actor, "auth_method": u.AuthMethod})
	if err != nil {
		return err
	}
	if err = appendEvent(ctx, tx, e); err != nil {
		return err
	}
	return tx.Commit()
}
