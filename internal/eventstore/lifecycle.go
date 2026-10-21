// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/cerber/internal/telemetry"
	"io"
	"os"
	"path/filepath"
	"time"
)

const maxArchiveBytes = 32 << 20
const evidenceIDs = `SELECT j.value FROM detections d,json_each(d.payload,'$.evidence') j`

func (s *Store) ConfigureArchive(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("archive directory must be absolute")
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.archiveConfigMu.Lock()
	defer s.archiveConfigMu.Unlock()
	if s.archiveDir != "" && s.archiveDir != path {
		return fmt.Errorf("archive directory cannot change while running")
	}
	if e := os.MkdirAll(path, 0700); e != nil {
		return e
	}
	st, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("archive directory must be a local directory, not a symlink")
	}
	s.archiveDir = path
	return nil
}
func (s *Store) archiveRoot() string {
	s.archiveConfigMu.RLock()
	defer s.archiveConfigMu.RUnlock()
	return s.archiveDir
}
func retentionPolicy(ctx context.Context, q rowQuery) (telemetry.RetentionPolicy, error) {
	var p telemetry.RetentionPolicy
	e := q.QueryRowContext(ctx, "SELECT enabled,hot_days,archive_days,version FROM event_retention WHERE id=1").Scan(&p.Enabled, &p.HotDays, &p.ArchiveDays, &p.Version)
	return p, e
}

type rowQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func lifecycleAudit(ctx context.Context, tx *sql.Tx, actor, action string, details any, now time.Time) error {
	b, e := json.Marshal(details)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO event_retention_audit(at,actor,action,details) VALUES(?,?,?,?)", stamp(now), actor, action, string(b))
	return e
}
func (s *Store) RetentionStatus(ctx context.Context) (telemetry.RetentionStatus, error) {
	var v telemetry.RetentionStatus
	var at sql.NullString
	e := s.db.QueryRowContext(ctx, `SELECT enabled,hot_days,archive_days,version,last_success_at,last_error,(SELECT count(*) FROM raw_events WHERE id IN (`+evidenceIDs+`)),(SELECT raw_bytes FROM journal_usage WHERE id=1),(SELECT count(*) FROM event_archives WHERE state IN ('active','expiring')) FROM event_retention WHERE id=1`).Scan(&v.Policy.Enabled, &v.Policy.HotDays, &v.Policy.ArchiveDays, &v.Policy.Version, &at, &v.LastError, &v.ProtectedEvents, &v.QuotaBytes, &v.Archives)
	v.ArchiveConfigured = s.archiveRoot() != ""
	if at.Valid {
		t, e2 := parseTime(at.String)
		if e2 != nil {
			return v, e2
		}
		v.LastSuccessAt = &t
	}
	return v, e
}
func parseTime(s string) (time.Time, error) { return time.Parse(time.RFC3339Nano, s) }
func (s *Store) SetRetention(ctx context.Context, p telemetry.RetentionPolicy, actor string, now time.Time) error {
	if p.Validate() != nil || actor == "" || len(actor) > 64 {
		return telemetry.ErrInvalid
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if p.Enabled && s.archiveRoot() == "" {
		return telemetry.ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	prior, e := retentionPolicy(ctx, tx)
	if e != nil {
		return e
	}
	if prior.Version != p.Version {
		return telemetry.ErrConflict
	}
	_, e = tx.ExecContext(ctx, "UPDATE event_retention SET enabled=?,hot_days=?,archive_days=?,version=version+1 WHERE id=1", p.Enabled, p.HotDays, p.ArchiveDays)
	if e != nil {
		return e
	}
	p.Version++
	if e = lifecycleAudit(ctx, tx, actor, "policy.updated", map[string]any{"before": prior, "after": p}, now); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) Archives(ctx context.Context, before int64) ([]telemetry.Archive, error) {
	if before < 0 {
		return nil, telemetry.ErrInvalid
	}
	rows, e := s.db.QueryContext(ctx, "SELECT sequence,id,created_at,records,bytes,sha256,first_sequence,last_sequence,state FROM event_archives WHERE (?=0 OR sequence<?) ORDER BY sequence DESC LIMIT 51", before, before)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []telemetry.Archive{}
	for rows.Next() {
		var a telemetry.Archive
		var at string
		if e = rows.Scan(&a.Sequence, &a.ID, &at, &a.Records, &a.Bytes, &a.SHA256, &a.FirstSequence, &a.LastSequence, &a.State); e != nil {
			return nil, e
		}
		a.CreatedAt, e = parseTime(at)
		if e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *Store) RetentionHistory(ctx context.Context, before int64) ([]telemetry.RetentionAudit, error) {
	if before < 0 {
		return nil, telemetry.ErrInvalid
	}
	rows, e := s.db.QueryContext(ctx, "SELECT sequence,at,actor,action,details FROM event_retention_audit WHERE (?=0 OR sequence<?) ORDER BY sequence DESC LIMIT 51", before, before)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []telemetry.RetentionAudit{}
	for rows.Next() {
		var a telemetry.RetentionAudit
		var at string
		if e = rows.Scan(&a.Sequence, &at, &a.Actor, &a.Action, &a.Details); e != nil {
			return nil, e
		}
		a.At, e = parseTime(at)
		if e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Maintain moves a bounded batch only after a synced, verified archive exists.
// Detections and all their evidence stay hot, including acknowledged/closed cases.
func (s *Store) Maintain(ctx context.Context, now time.Time) (count int, err error) {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	defer func() {
		if err != nil && ctx.Err() == nil {
			s.db.ExecContext(ctx, "UPDATE event_retention SET last_error='Обслуживание прервано; проверьте журнал сервера и архивный каталог' WHERE id=1")
		}
	}()
	p, e := retentionPolicy(ctx, s.db)
	if e != nil {
		return 0, e
	}
	if !p.Enabled {
		return 0, nil
	}
	root := s.archiveRoot()
	if root == "" {
		return 0, fmt.Errorf("archive directory not configured")
	}
	count, e = s.archiveBatch(ctx, root, p, now)
	if e != nil {
		return 0, e
	}
	if e = s.expireArchives(ctx, root, p, now); e != nil {
		return count, e
	}
	_, e = s.db.ExecContext(ctx, "UPDATE event_retention SET last_success_at=?,last_error='' WHERE id=1", stamp(now))
	return count, e
}
func (s *Store) archiveBatch(ctx context.Context, root string, p telemetry.RetentionPolicy, now time.Time) (int, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()
	cutoff := stamp(now.Add(-time.Duration(p.HotDays) * 24 * time.Hour))
	rows, e := tx.QueryContext(ctx, `SELECT r.sequence,r.id,r.agent_id,r.asset_id,r.received_at,r.payload,n.payload FROM raw_events r JOIN normalized_events n ON n.sequence=r.sequence WHERE r.received_at<? AND n.event_time<? AND r.sequence<=(SELECT CASE WHEN count(*)=2 THEN min(position) ELSE -1 END FROM consumer_cursors WHERE name IN ('normalizer/1','correlator/1')) AND r.id NOT IN (`+evidenceIDs+`) ORDER BY r.sequence LIMIT 250`, cutoff, cutoff)
	if e != nil {
		return 0, e
	}
	items := []telemetry.ArchiveRecord{}
	var rawBytes int64
	for rows.Next() {
		var a telemetry.ArchiveRecord
		var at, raw, n string
		a.SchemaVersion = 1
		if e = rows.Scan(&a.Sequence, &a.ID, &a.AgentID, &a.AssetID, &at, &raw, &n); e != nil {
			rows.Close()
			return 0, e
		}
		a.ReceivedAt, e = parseTime(at)
		if e == nil {
			e = json.Unmarshal([]byte(raw), &a.Raw)
		}
		if e == nil {
			e = json.Unmarshal([]byte(n), &a.Normalized)
		}
		if e != nil {
			rows.Close()
			return 0, e
		}
		items = append(items, a)
		rawBytes += int64(len(raw))
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return 0, e
	}
	if len(items) == 0 {
		return 0, nil
	}
	var nonce [32]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return 0, e
	}
	id := hex.EncodeToString(nonce[:])
	tmp := filepath.Join(root, ".pending-"+id)
	final := filepath.Join(root, id+".jsonl.gz")
	f, e := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return 0, e
	}
	defer os.Remove(tmp)
	z := gzip.NewWriter(f)
	encoder := json.NewEncoder(z)
	for _, a := range items {
		if e = encoder.Encode(a); e != nil {
			z.Close()
			f.Close()
			return 0, e
		}
	}
	if e = z.Close(); e != nil {
		f.Close()
		return 0, e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return 0, e
	}
	if e = f.Close(); e != nil {
		return 0, e
	}
	data, e := readBounded(tmp)
	if e != nil {
		return 0, e
	}
	if e = verifyRecords(data, items); e != nil {
		return 0, e
	}
	digest := sha256.Sum256(data)
	if e = publishArchive(tmp, final); e != nil {
		return 0, e
	}
	a := telemetry.Archive{ID: id, CreatedAt: now, Records: len(items), Bytes: int64(len(data)), SHA256: hex.EncodeToString(digest[:]), FirstSequence: items[0].Sequence, LastSequence: items[len(items)-1].Sequence, State: "active"}
	archiveResult, e := tx.ExecContext(ctx, "INSERT INTO event_archives(id,created_at,records,bytes,sha256,first_sequence,last_sequence,state) VALUES(?,?,?,?,?,?,?,'active')", a.ID, stamp(now), a.Records, a.Bytes, a.SHA256, a.FirstSequence, a.LastSequence)
	if e != nil {
		return 0, e
	}
	a.Sequence, e = archiveResult.LastInsertId()
	if e != nil {
		return 0, e
	}
	for _, v := range items {
		digest, e := sourceDigest(v.Raw)
		if e != nil {
			return 0, e
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO retired_events VALUES(?,?,?,?,?,?)", v.ID, v.AgentID, v.Raw.Source, v.Raw.Cursor, digest, id); e != nil {
			return 0, e
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM normalized_events WHERE sequence=?", v.Sequence); e != nil {
			return 0, e
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM raw_events WHERE sequence=?", v.Sequence); e != nil {
			return 0, e
		}
	}
	usageResult, e := tx.ExecContext(ctx, "UPDATE journal_usage SET raw_bytes=raw_bytes-? WHERE id=1 AND raw_bytes>=?", rawBytes, rawBytes)
	if e != nil {
		return 0, e
	}
	affected, e := usageResult.RowsAffected()
	if e != nil {
		return 0, e
	}
	if affected != 1 {
		return 0, fmt.Errorf("event usage accounting inconsistent")
	}
	if e = lifecycleAudit(ctx, tx, "retention", "events.archived", map[string]any{"archive": a, "policy_version": p.Version}, now); e != nil {
		return 0, e
	}
	if e = tx.Commit(); e != nil {
		return 0, e
	}
	return len(items), nil
}
func readBounded(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, maxArchiveBytes+1))
	if e != nil {
		return nil, e
	}
	if len(b) > maxArchiveBytes {
		return nil, fmt.Errorf("archive size exceeds limit")
	}
	return b, nil
}
func verifyRecords(data []byte, expected []telemetry.ArchiveRecord) error {
	z, e := gzip.NewReader(bytes.NewReader(data))
	if e != nil {
		return e
	}
	defer z.Close()
	d := json.NewDecoder(io.LimitReader(z, 64<<20))
	for _, v := range expected {
		var got telemetry.ArchiveRecord
		if e = d.Decode(&got); e != nil {
			return e
		}
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(v)
		if !bytes.Equal(a, b) {
			return fmt.Errorf("archive verification failed")
		}
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fmt.Errorf("archive has unexpected records")
	}
	return nil
}
func (s *Store) ReadArchive(ctx context.Context, id string) ([]byte, telemetry.Archive, error) {
	var a telemetry.Archive
	if !telemetry.Identifier(id) {
		return nil, a, telemetry.ErrInvalid
	}
	var at string
	e := s.db.QueryRowContext(ctx, "SELECT sequence,id,created_at,records,bytes,sha256,first_sequence,last_sequence,state FROM event_archives WHERE id=?", id).Scan(&a.Sequence, &a.ID, &at, &a.Records, &a.Bytes, &a.SHA256, &a.FirstSequence, &a.LastSequence, &a.State)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, a, telemetry.ErrNotFound
	}
	if e != nil {
		return nil, a, e
	}
	a.CreatedAt, _ = parseTime(at)
	if a.State == "expired" {
		return nil, a, telemetry.ErrExpired
	}
	root := s.archiveRoot()
	if root == "" {
		return nil, a, fmt.Errorf("archive directory unavailable")
	}
	data, e := readBounded(filepath.Join(root, id+".jsonl.gz"))
	if e != nil {
		return nil, a, e
	}
	sum := sha256.Sum256(data)
	if int64(len(data)) != a.Bytes || hex.EncodeToString(sum[:]) != a.SHA256 {
		return nil, a, fmt.Errorf("archive checksum mismatch")
	}
	return data, a, nil
}
func (s *Store) readArchivedRaw(ctx context.Context, id string) (telemetry.RawRecord, error) {
	var r telemetry.RawRecord
	var archive string
	e := s.db.QueryRowContext(ctx, "SELECT archive_id FROM retired_events WHERE id=?", id).Scan(&archive)
	if errors.Is(e, sql.ErrNoRows) {
		return r, telemetry.ErrNotFound
	}
	if e != nil {
		return r, e
	}
	data, _, e := s.ReadArchive(ctx, archive)
	if e != nil {
		return r, e
	}
	z, e := gzip.NewReader(bytes.NewReader(data))
	if e != nil {
		return r, e
	}
	defer z.Close()
	d := json.NewDecoder(io.LimitReader(z, 64<<20))
	for {
		var a telemetry.ArchiveRecord
		e = d.Decode(&a)
		if e == io.EOF {
			break
		}
		if e != nil {
			return r, e
		}
		if a.ID == id {
			return telemetry.RawRecord{Sequence: a.Sequence, AgentID: a.AgentID, AssetID: a.AssetID, ReceivedAt: a.ReceivedAt, Raw: a.Raw, Archived: true, ArchiveID: archive}, nil
		}
	}
	return r, fmt.Errorf("event missing in archive")
}

func (s *Store) expireArchives(ctx context.Context, root string, p telemetry.RetentionPolicy, now time.Time) error {
	cutoff := stamp(now.Add(-time.Duration(p.ArchiveDays) * 24 * time.Hour))
	rows, e := s.db.QueryContext(ctx, "SELECT id FROM event_archives WHERE state='expiring' OR (state='active' AND ?<>0 AND created_at<?) ORDER BY sequence LIMIT 20", p.ArchiveDays, cutoff)
	if e != nil {
		return e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, id := range ids {
		if !telemetry.Identifier(id) {
			return telemetry.ErrInvalid
		}
		var state, at string
		e = s.db.QueryRowContext(ctx, "SELECT state,created_at FROM event_archives WHERE id=?", id).Scan(&state, &at)
		if e != nil {
			return e
		}
		path := filepath.Join(root, id+".jsonl.gz")
		_, fileError := os.Stat(path)
		missing := os.IsNotExist(fileError)
		if fileError != nil && !missing {
			return fileError
		}
		if !missing {
			if _, _, e = s.ReadArchive(ctx, id); e != nil {
				return e
			}
		} else if state != "expiring" {
			return fmt.Errorf("active archive file missing")
		}
		if state == "active" {
			tx, e := s.db.BeginTx(ctx, nil)
			if e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, "UPDATE event_archives SET state='expiring' WHERE id=? AND state='active'", id); e == nil {
				e = lifecycleAudit(ctx, tx, "retention", "archive.expiring", map[string]string{"id": id}, now)
			}
			if e == nil {
				e = tx.Commit()
			} else {
				tx.Rollback()
			}
			if e != nil {
				return e
			}
		}
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		current, e := retentionPolicy(ctx, tx)
		if e != nil {
			tx.Rollback()
			return e
		}
		if current.Version != p.Version {
			tx.Rollback()
			return telemetry.ErrConflict
		}
		created, _ := parseTime(at)
		expire := p.Enabled && p.ArchiveDays > 0 && created.Before(now.Add(-time.Duration(p.ArchiveDays)*24*time.Hour))
		next, action := "active", "archive.expiration_canceled"
		if missing || expire {
			if !missing {
				if e = os.Remove(path); e != nil && !os.IsNotExist(e) {
					tx.Rollback()
					return e
				}
				if e = syncArchiveDirectory(root); e != nil {
					tx.Rollback()
					return e
				}
			}
			next, action = "expired", "archive.expired"
		}
		_, e = tx.ExecContext(ctx, "UPDATE event_archives SET state=? WHERE id=?", next, id)
		if e == nil {
			e = lifecycleAudit(ctx, tx, "retention", action, map[string]string{"id": id}, now)
		}
		if e == nil {
			e = tx.Commit()
		} else {
			tx.Rollback()
		}
		if e != nil {
			return e
		}
	}
	return nil
}

// MaintainRequested records the authenticated requester before running the same bounded worker.
func (s *Store) MaintainRequested(ctx context.Context, actor string, now time.Time) (int, error) {
	if actor == "" || len(actor) > 64 {
		return 0, telemetry.ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return 0, e
	}
	if e = lifecycleAudit(ctx, tx, actor, "maintenance.requested", map[string]any{}, now); e != nil {
		tx.Rollback()
		return 0, e
	}
	if e = tx.Commit(); e != nil {
		return 0, e
	}
	return s.Maintain(ctx, now)
}
