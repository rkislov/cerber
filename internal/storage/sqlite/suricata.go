// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/event"
	"github.com/rkislov/cerber/internal/ingest"
	rules "github.com/rkislov/cerber/internal/suricatarules"
)

func initSuricata(ctx context.Context, tx *sql.Tx) error {
	if _, e := tx.ExecContext(ctx, suricataSchema); e != nil {
		return e
	}
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO suricata_signer VALUES(1,?)", []byte(key))
	return e
}
func suricataAdmin(ctx context.Context, tx *sql.Tx) (admin.User, error) {
	u, ok := admin.Principal(ctx)
	if !ok || u.Username == "" || u.Role != "administrator" {
		return u, admin.ErrForbidden
	}
	return u, checkAdmin(ctx, tx, true)
}
func (s *Store) SuricataCatalog(ctx context.Context) ([]rules.Manifest, string, error) {
	var key []byte
	if e := s.db.QueryRowContext(ctx, "SELECT private_key FROM suricata_signer WHERE id=1").Scan(&key); e != nil {
		return nil, "", e
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, "", rules.ErrInvalid
	}
	rows, e := s.db.QueryContext(ctx, "SELECT manifest FROM suricata_bundles ORDER BY json_extract(manifest,'$.created_at') DESC,id LIMIT ?", rules.MaxVersions)
	if e != nil {
		return nil, "", e
	}
	defer rows.Close()
	items := []rules.Manifest{}
	for rows.Next() {
		var b string
		var m rules.Manifest
		if e = rows.Scan(&b); e != nil {
			return nil, "", e
		}
		if e = json.Unmarshal([]byte(b), &m); e != nil {
			return nil, "", e
		}
		items = append(items, m)
	}
	return items, base64.StdEncoding.EncodeToString(ed25519.PrivateKey(key).Public().(ed25519.PublicKey)), rows.Err()
}
func suricataBundle(ctx context.Context, q rowQuerier, id string) (rules.Bundle, error) {
	var b rules.Bundle
	var m string
	e := q.QueryRowContext(ctx, "SELECT manifest,data FROM suricata_bundles WHERE id=?", id).Scan(&m, &b.Data)
	if errors.Is(e, sql.ErrNoRows) {
		e = rules.ErrNotFound
	}
	if e == nil {
		e = json.Unmarshal([]byte(m), &b.Manifest)
	}
	return b, e
}
func (s *Store) SuricataBundle(ctx context.Context, id string) (rules.Bundle, error) {
	return suricataBundle(ctx, s.db, id)
}
func (s *Store) PutSuricataBundle(ctx context.Context, b rules.Bundle) (rules.Manifest, error) {
	if _, e := rules.Unpack(b.Manifest, b.Data); e != nil {
		return rules.Manifest{}, e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return rules.Manifest{}, e
	}
	defer tx.Rollback()
	u, e := suricataAdmin(ctx, tx)
	if e != nil {
		return rules.Manifest{}, e
	}
	m, e := putSuricataBundle(ctx, tx, b, u.Username, false)
	if e != nil {
		return m, e
	}
	return m, tx.Commit()
}

// Caller must validate the bundle outside the write transaction.
func putSuricataBundle(ctx context.Context, tx *sql.Tx, b rules.Bundle, actor string, automatic bool) (rules.Manifest, error) {
	var e error
	if old, e := suricataBundle(ctx, tx, b.Manifest.ID); e == nil {
		return old.Manifest, nil
	} else if !errors.Is(e, rules.ErrNotFound) {
		return rules.Manifest{}, e
	}
	var count, size int
	if e = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(length(data)),0) FROM suricata_bundles").Scan(&count, &size); e != nil {
		return rules.Manifest{}, e
	}
	if automatic {
		for count >= rules.MaxVersions || size+len(b.Data) > rules.MaxStorage {
			var id string
			var bytes int
			rows, e := tx.QueryContext(ctx, "SELECT b.id,length(b.data) FROM suricata_bundles b JOIN suricata_auto_bundles a ON a.id=b.id ORDER BY json_extract(b.manifest,'$.created_at'),b.id")
			if e != nil {
				return rules.Manifest{}, e
			}
			type candidate struct {
				id    string
				bytes int
			}
			var candidates []candidate
			for rows.Next() {
				var c candidate
				if e = rows.Scan(&c.id, &c.bytes); e != nil {
					rows.Close()
					return rules.Manifest{}, e
				}
				candidates = append(candidates, c)
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return rules.Manifest{}, e
			}
			for _, c := range candidates {
				used, e := suricataBundleUsed(ctx, tx, c.id)
				if e != nil {
					return rules.Manifest{}, e
				}
				if !used {
					id = c.id
					bytes = c.bytes
					break
				}
			}
			if id == "" {
				return rules.Manifest{}, rules.ErrLimit
			}
			if _, e = tx.ExecContext(ctx, "DELETE FROM suricata_bundles WHERE id=?", id); e != nil {
				return rules.Manifest{}, e
			}
			if e = suricataAudit(ctx, tx, "suricata.auto_pruned", id, actor, map[string]string{"id": id}); e != nil {
				return rules.Manifest{}, e
			}
			count--
			size -= bytes
		}
	}
	if count >= rules.MaxVersions || size+len(b.Data) > rules.MaxStorage {
		return rules.Manifest{}, rules.ErrLimit
	}
	var key []byte
	if e = tx.QueryRowContext(ctx, "SELECT private_key FROM suricata_signer WHERE id=1").Scan(&key); e != nil {
		return rules.Manifest{}, e
	}
	if len(key) != ed25519.PrivateKeySize {
		return rules.Manifest{}, rules.ErrInvalid
	}
	b.Manifest.CreatedAt = time.Now().UTC()
	b.Manifest.CreatedBy = actor
	b.Manifest.Sign(ed25519.PrivateKey(key))
	m, _ := json.Marshal(b.Manifest)
	if _, e = tx.ExecContext(ctx, "INSERT INTO suricata_bundles VALUES(?,?,?)", b.Manifest.ID, string(m), b.Data); e != nil {
		return rules.Manifest{}, e
	}
	if e = suricataAudit(ctx, tx, "suricata.bundle_created", b.Manifest.ID, actor, b.Manifest); e != nil {
		return rules.Manifest{}, e
	}
	if automatic {
		if _, e = tx.ExecContext(ctx, "INSERT INTO suricata_auto_bundles VALUES(?)", b.Manifest.ID); e != nil {
			return rules.Manifest{}, e
		}
	}
	return b.Manifest, nil
}

func suricataAssignment(ctx context.Context, q rowQuerier, id string) (rules.Assignment, error) {
	var a rules.Assignment
	var p string
	e := q.QueryRowContext(ctx, "SELECT payload FROM suricata_assignments WHERE agent_id=?", id).Scan(&p)
	if errors.Is(e, sql.ErrNoRows) {
		return a, nil
	}
	if e == nil {
		e = json.Unmarshal([]byte(p), &a)
	}
	return a, e
}
func (s *Store) SuricataAssignment(ctx context.Context, id string) (rules.Assignment, error) {
	return suricataAssignment(ctx, s.db, id)
}
func (s *Store) AssignSuricata(ctx context.Context, c rules.Change) (rules.Assignment, error) {
	var a rules.Assignment
	if !ingest.Identifier(c.AgentID) || c.ExpectedRevision < 0 || c.ExpectedRevision >= 1<<53-1 || !c.Rollback && !rules.ValidID(c.BundleID) {
		return a, rules.ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return a, e
	}
	defer tx.Rollback()
	u, e := suricataAdmin(ctx, tx)
	if e != nil {
		return a, e
	}
	a, e = assignSuricata(ctx, tx, c, u.Username, "", 0)
	if e != nil {
		return a, e
	}
	return a, tx.Commit()
}
func assignSuricata(ctx context.Context, tx *sql.Tx, c rules.Change, actor, groupID string, groupRevision int64) (rules.Assignment, error) {
	var a rules.Assignment
	old, e := suricataAssignment(ctx, tx, c.AgentID)
	if e != nil {
		return a, e
	}
	if old.Revision != c.ExpectedRevision {
		return a, rules.ErrConflict
	}
	var payload string
	var revoked bool
	e = tx.QueryRowContext(ctx, "SELECT h.payload,a.revoked FROM agents a JOIN agent_heartbeats h ON h.agent_id=a.id WHERE a.id=?", c.AgentID).Scan(&payload, &revoked)
	if errors.Is(e, sql.ErrNoRows) {
		return a, rules.ErrNotFound
	}
	if e != nil {
		return a, e
	}
	var h ingest.Heartbeat
	if json.Unmarshal([]byte(payload), &h) != nil || h.Sensor == nil || h.Sensor.Rules == nil || h.Sensor.Rules.State == "unconfigured" || revoked {
		return a, rules.ErrConflict
	}
	if groupID == "" {
		owners, e := matchingSuricataGroups(ctx, tx, c.AgentID, h.Sensor.Rules.EngineMajor)
		if e != nil {
			return a, e
		}
		if len(owners) > 0 {
			return a, rules.ErrConflict
		}
	}
	if c.Rollback {
		c.BundleID = old.PreviousID
	}
	b, e := suricataBundle(ctx, tx, c.BundleID)
	if e != nil {
		return a, e
	}
	if h.Sensor.Rules.EngineMajor != b.Manifest.EngineMajor {
		return a, rules.ErrInvalid
	}
	previous := h.Sensor.Rules.AppliedID
	if previous == c.BundleID {
		previous = old.PreviousID
		if previous == c.BundleID {
			previous = ""
		}
	}
	a = rules.Assignment{GroupID: groupID, GroupRevision: groupRevision, Revision: old.Revision + 1, Bundle: b.Manifest, PreviousID: previous, UpdatedAt: time.Now().UTC(), UpdatedBy: actor}
	p, _ := json.Marshal(a)
	if _, e = tx.ExecContext(ctx, "INSERT INTO suricata_assignments VALUES(?,?) ON CONFLICT(agent_id) DO UPDATE SET payload=excluded.payload", c.AgentID, string(p)); e != nil {
		return a, e
	}
	kind := "suricata.assigned"
	if c.Rollback {
		kind = "suricata.rollback_requested"
	}
	if e = suricataAudit(ctx, tx, kind, c.AgentID, actor, a); e != nil {
		return a, e
	}
	if e = suricataHistory(ctx, tx, c.AgentID, kind, a); e != nil {
		return a, e
	}
	return a, nil
}

func (s *Store) DeleteSuricataBundle(ctx context.Context, id string) error {
	if !rules.ValidID(id) {
		return rules.ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	u, e := suricataAdmin(ctx, tx)
	if e != nil {
		return e
	}
	used, e := suricataBundleUsed(ctx, tx, id)
	if e != nil {
		return e
	}
	if used {
		return rules.ErrConflict
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM suricata_bundles WHERE id=?", id); e != nil {
		return e
	}
	if e = suricataAudit(ctx, tx, "suricata.bundle_deleted", id, u.Username, map[string]string{"id": id}); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) AssignedSuricataBundle(ctx context.Context, id, hash, bundle string) ([]byte, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if _, e = agentBinding(ctx, tx, id, hash); e != nil {
		return nil, e
	}
	a, e := suricataAssignment(ctx, tx, id)
	if e != nil {
		return nil, e
	}
	if a.Bundle.ID != bundle {
		return nil, ingest.ErrUnauthorized
	}
	b, e := suricataBundle(ctx, tx, bundle)
	return b.Data, e
}
func suricataAudit(ctx context.Context, tx *sql.Tx, kind, id, actor string, v any) error {
	ev, e := event.New(kind, id, v)
	if e != nil {
		return e
	}
	ev.Source = "admin:" + actor
	return appendEvent(ctx, tx, ev)
}
func suricataHistory(ctx context.Context, tx *sql.Tx, id, kind string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO suricata_history(agent_id,at,kind,payload) VALUES(?,?,?,?)", id, stamp(time.Now()), kind, string(b))
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, "DELETE FROM suricata_history WHERE agent_id=? AND seq NOT IN (SELECT seq FROM suricata_history WHERE agent_id=? ORDER BY seq DESC LIMIT 50)", id, id)
	return e
}
func (s *Store) SuricataHistory(ctx context.Context, id string) ([]map[string]any, error) {
	rows, e := s.db.QueryContext(ctx, "SELECT at,kind,payload FROM suricata_history WHERE agent_id=? ORDER BY seq DESC LIMIT 50", id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var at, kind, p string
		if e = rows.Scan(&at, &kind, &p); e != nil {
			return nil, e
		}
		items = append(items, map[string]any{"at": at, "kind": kind, "data": json.RawMessage(p)})
	}
	return items, rows.Err()
}

func suricataBundleUsed(ctx context.Context, tx *sql.Tx, id string) (bool, error) {
	var used int
	e := tx.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM suricata_assignments WHERE json_extract(payload,'$.bundle.id')=? OR json_extract(payload,'$.previous_id')=?) +
 (SELECT count(*) FROM agent_heartbeats WHERE json_extract(payload,'$.sensor.suricata.applied_id')=?) +
 (SELECT count(*) FROM suricata_feeds WHERE json_extract(payload,'$.latest_id')=?) +
 (SELECT count(*) FROM suricata_group_rules WHERE json_extract(payload,'$.active_id')=? OR json_extract(payload,'$.previous_id')=? OR json_extract(payload,'$.custom_id')=? OR json_extract(payload,'$.bundle_id')=? OR json_extract(payload,'$.built_et_id')=?)`, id, id, id, id, id, id, id, id, id).Scan(&used)
	return used > 0, e
}
