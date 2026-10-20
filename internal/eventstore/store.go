// SPDX-License-Identifier: Apache-2.0
// Package eventstore is the SQLite event-journal adapter for small installations.
// It deliberately uses a separate database from inventory/control-plane data.
package eventstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rkislov/cerber/internal/correlation"
	"github.com/rkislov/cerber/internal/telemetry"
	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

func Open(ctx context.Context, path string) (*Store, error) {
	if path != ":memory:" {
		if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			return nil, e
		}
		f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
		if e != nil {
			return nil, e
		}
		f.Close()
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	s := &Store{db}
	for _, q := range []string{"PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL"} {
		if _, e = db.ExecContext(ctx, q); e != nil {
			db.Close()
			return nil, e
		}
	}
	var version int
	if e = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); e != nil || version > 1 {
		db.Close()
		return nil, fmt.Errorf("unsupported event database version: %d: %v", version, e)
	}
	_, e = db.ExecContext(ctx, schema)
	if e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func (s *Store) Close() error  { return s.db.Close() }
func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000000Z") }

const schema = `
CREATE TABLE IF NOT EXISTS raw_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,agent_id TEXT NOT NULL,asset_id TEXT NOT NULL,source TEXT NOT NULL,cursor TEXT NOT NULL,received_at TEXT NOT NULL,payload TEXT NOT NULL CHECK(json_valid(payload)),UNIQUE(agent_id,source,cursor));
CREATE TABLE IF NOT EXISTS journal_usage(id INTEGER PRIMARY KEY CHECK(id=1),raw_bytes INTEGER NOT NULL);
INSERT OR IGNORE INTO journal_usage VALUES(1,0);
CREATE TABLE IF NOT EXISTS batch_receipts(agent_id TEXT NOT NULL,id TEXT NOT NULL,digest TEXT NOT NULL,receipt TEXT NOT NULL,PRIMARY KEY(agent_id,id));
CREATE TABLE IF NOT EXISTS consumer_cursors(name TEXT PRIMARY KEY,position INTEGER NOT NULL);
INSERT OR IGNORE INTO consumer_cursors VALUES('normalizer/1',0),('correlator/1',0);
CREATE TABLE IF NOT EXISTS normalized_events(sequence INTEGER PRIMARY KEY,id TEXT UNIQUE NOT NULL,agent_id TEXT NOT NULL,class TEXT NOT NULL,status TEXT NOT NULL,outcome TEXT NOT NULL,user_name TEXT NOT NULL,source_ip TEXT NOT NULL,event_time TEXT NOT NULL,payload TEXT NOT NULL CHECK(json_valid(payload)));
CREATE INDEX IF NOT EXISTS normalized_auth ON normalized_events(agent_id,user_name,source_ip,event_time) WHERE class='authentication' AND status='parsed' AND outcome='failure';
CREATE TABLE IF NOT EXISTS detections(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,rule TEXT NOT NULL,agent_id TEXT NOT NULL,user_name TEXT NOT NULL,source_ip TEXT NOT NULL,event_time TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open','acknowledged')),acknowledged_by TEXT NOT NULL DEFAULT '',payload TEXT NOT NULL CHECK(json_valid(payload)));
CREATE INDEX IF NOT EXISTS detection_suppress ON detections(rule,agent_id,user_name,source_ip,event_time);
CREATE TABLE IF NOT EXISTS source_cursors(agent_id TEXT NOT NULL,source TEXT NOT NULL,cursor TEXT NOT NULL,PRIMARY KEY(agent_id,source));
CREATE TABLE IF NOT EXISTS event_spool(sequence INTEGER PRIMARY KEY AUTOINCREMENT,agent_id TEXT NOT NULL,id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL CHECK(json_valid(payload)));
CREATE TABLE IF NOT EXISTS detection_audit(sequence INTEGER PRIMARY KEY AUTOINCREMENT,detection_id TEXT NOT NULL,actor TEXT NOT NULL,at TEXT NOT NULL);
PRAGMA user_version=1;`

// Accept acknowledges only after raw records and immutable receipt are committed.
func (s *Store) Accept(ctx context.Context, agent, asset string, b telemetry.Batch) (telemetry.Receipt, error) {
	var receipt telemetry.Receipt
	if b.AgentID != agent || asset == "" {
		return receipt, telemetry.ErrInvalid
	}
	if e := b.Validate(); e != nil {
		return receipt, e
	}
	data, _ := json.Marshal(b)
	digest := telemetry.ID(string(data))
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return receipt, e
	}
	defer tx.Rollback()
	var prior, encoded string
	e = tx.QueryRowContext(ctx, "SELECT digest,receipt FROM batch_receipts WHERE agent_id=? AND id=?", agent, b.ID).Scan(&prior, &encoded)
	if e == nil {
		if prior != digest {
			return receipt, telemetry.ErrConflict
		}
		e = json.Unmarshal([]byte(encoded), &receipt)
		return receipt, e
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return receipt, e
	}
	now := time.Now().UTC()
	var rawBytes int64
	if e = tx.QueryRowContext(ctx, "SELECT raw_bytes FROM journal_usage WHERE id=1").Scan(&rawBytes); e != nil {
		return receipt, e
	}
	initialBytes := rawBytes
	for _, r := range b.Records {
		id := telemetry.ID(agent, r.ID)
		p, _ := json.Marshal(r)
		var stored string
		e = tx.QueryRowContext(ctx, "SELECT payload FROM raw_events WHERE id=? OR (agent_id=? AND source=? AND cursor=?)", id, agent, r.Source, r.Cursor).Scan(&stored)
		if e == nil {
			if stored != string(p) {
				return receipt, telemetry.ErrConflict
			}
			continue
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return receipt, e
		}
		rawBytes += int64(len(p))
		if rawBytes > 1<<30 {
			return receipt, telemetry.ErrFull
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO raw_events(id,agent_id,asset_id,source,cursor,received_at,payload) VALUES(?,?,?,?,?,?,?)", id, agent, asset, r.Source, r.Cursor, stamp(now), string(p)); e != nil {
			return receipt, e
		}
	}
	receipt = telemetry.Receipt{BatchID: b.ID, AgentID: agent, Count: len(b.Records), ReceivedAt: now}
	p, _ := json.Marshal(receipt)
	rawBytes += int64(len(p)) + 256
	if rawBytes > 1<<30 {
		return receipt, telemetry.ErrFull
	}
	if _, e = tx.ExecContext(ctx, "UPDATE journal_usage SET raw_bytes=raw_bytes+? WHERE id=1", rawBytes-initialBytes); e != nil {
		return receipt, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO batch_receipts VALUES(?,?,?,?)", agent, b.ID, digest, string(p)); e != nil {
		return receipt, e
	}
	return receipt, tx.Commit()
}
func (s *Store) SourceCursor(ctx context.Context, agent, source string) (string, error) {
	var c string
	e := s.db.QueryRowContext(ctx, "SELECT cursor FROM source_cursors WHERE agent_id=? AND source=?", agent, source).Scan(&c)
	if errors.Is(e, sql.ErrNoRows) {
		return "", nil
	}
	return c, e
}

// Enqueue advances source position in the same durable transaction as its batch.
// expected is a compare-and-set guard against two collectors reading one source.
func (s *Store) Enqueue(ctx context.Context, b telemetry.Batch, source, expected, next string) error {
	if e := b.Validate(); e != nil {
		return e
	}
	if !telemetry.ValidSource(source) || next == "" {
		return telemetry.ErrInvalid
	}
	for _, r := range b.Records {
		if r.Source != source {
			return telemetry.ErrInvalid
		}
	}
	if b.Records[len(b.Records)-1].Cursor != next {
		return telemetry.ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var current string
	e = tx.QueryRowContext(ctx, "SELECT cursor FROM source_cursors WHERE agent_id=? AND source=?", b.AgentID, source).Scan(&current)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if current != expected {
		return telemetry.ErrConflict
	}
	var count, size int64
	if e = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(length(payload)),0) FROM event_spool").Scan(&count, &size); e != nil {
		return e
	}
	p, _ := json.Marshal(b)
	if count >= 1000 || size+int64(len(p)) > 256<<20 {
		return telemetry.ErrFull
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO event_spool(agent_id,id,payload) VALUES(?,?,?)", b.AgentID, b.ID, string(p)); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO source_cursors VALUES(?,?,?) ON CONFLICT(agent_id,source) DO UPDATE SET cursor=excluded.cursor", b.AgentID, source, next)
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) NextBatch(ctx context.Context, agent string) (telemetry.Batch, error) {
	var b telemetry.Batch
	var p string
	e := s.db.QueryRowContext(ctx, "SELECT payload FROM event_spool WHERE agent_id=? ORDER BY sequence LIMIT 1", agent).Scan(&p)
	if errors.Is(e, sql.ErrNoRows) {
		return b, telemetry.ErrNotFound
	}
	if e != nil {
		return b, e
	}
	e = json.Unmarshal([]byte(p), &b)
	return b, e
}
func (s *Store) Ack(ctx context.Context, b telemetry.Batch, r telemetry.Receipt) error {
	if r.AgentID != b.AgentID || r.BatchID != b.ID || r.Count != len(b.Records) || r.ReceivedAt.IsZero() {
		return telemetry.ErrInvalid
	}
	_, e := s.db.ExecContext(ctx, "DELETE FROM event_spool WHERE agent_id=? AND id=?", b.AgentID, b.ID)
	return e
}

// Step independently commits bounded normalization and correlation progress.
func (s *Store) Step(ctx context.Context) error {
	for _, stage := range []string{"normalizer/1", "correlator/1"} {
		if e := s.step(ctx, stage); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) step(ctx context.Context, stage string) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var cursor int64
	if e = tx.QueryRowContext(ctx, "SELECT position FROM consumer_cursors WHERE name=?", stage).Scan(&cursor); e != nil {
		return e
	}
	type item struct {
		seq                 int64
		agent, asset, at, p string
	}
	items := []item{}
	query := "SELECT sequence,agent_id,asset_id,received_at,payload FROM raw_events WHERE sequence>? ORDER BY sequence LIMIT 100"
	if stage == "correlator/1" {
		query = "SELECT sequence,'','','',payload FROM normalized_events WHERE sequence>? ORDER BY sequence LIMIT 100"
	}
	rows, e := tx.QueryContext(ctx, query, cursor)
	if e != nil {
		return e
	}
	for rows.Next() {
		var v item
		if e = rows.Scan(&v.seq, &v.agent, &v.asset, &v.at, &v.p); e != nil {
			rows.Close()
			return e
		}
		items = append(items, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, v := range items {
		if stage == "normalizer/1" {
			var r telemetry.Raw
			if e = json.Unmarshal([]byte(v.p), &r); e != nil {
				return e
			}
			at, e := time.Parse(time.RFC3339Nano, v.at)
			if e != nil {
				return e
			}
			n := telemetry.Normalize(telemetry.RawRecord{Sequence: v.seq, AgentID: v.agent, AssetID: v.asset, ReceivedAt: at, Raw: r})
			p, _ := json.Marshal(n)
			_, e = tx.ExecContext(ctx, "INSERT INTO normalized_events VALUES(?,?,?,?,?,?,?,?,?,?)", v.seq, n.ID, n.AgentID, n.Class, n.Status, n.Outcome, n.User, n.SourceIP, stamp(n.EventTime), string(p))
			if e != nil {
				return e
			}
		} else {
			var n telemetry.Normalized
			if e = json.Unmarshal([]byte(v.p), &n); e != nil {
				return e
			}
			if n.Status == "parsed" {
				if e = correlate(ctx, tx, n); e != nil {
					return e
				}
			}
		}
		cursor = v.seq
	}
	if _, e = tx.ExecContext(ctx, "UPDATE consumer_cursors SET position=? WHERE name=?", cursor, stage); e != nil {
		return e
	}
	return tx.Commit()
}
func correlate(ctx context.Context, tx *sql.Tx, n telemetry.Normalized) error {
	failures := []telemetry.Normalized{}
	if n.Class == "authentication" && n.User != "" && n.SourceIP != "" {
		rows, e := tx.QueryContext(ctx, `SELECT payload FROM normalized_events WHERE class='authentication' AND status='parsed' AND outcome='failure' AND agent_id=? AND user_name=? AND source_ip=? AND event_time>=? AND event_time<=? AND sequence<=? ORDER BY event_time,sequence LIMIT 100`, n.AgentID, n.User, n.SourceIP, stamp(n.EventTime.Add(-correlation.Window)), stamp(n.EventTime), n.Sequence)
		if e != nil {
			return e
		}
		for rows.Next() {
			var p string
			var f telemetry.Normalized
			if e = rows.Scan(&p); e != nil {
				rows.Close()
				return e
			}
			if e = json.Unmarshal([]byte(p), &f); e != nil {
				rows.Close()
				return e
			}
			failures = append(failures, f)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
	}
	d := correlation.Evaluate(n, failures)
	if d == nil {
		return nil
	}
	if d.Rule == "auth.repeated_failures" {
		var count int
		if e := tx.QueryRowContext(ctx, "SELECT count(*) FROM detections WHERE rule=? AND agent_id=? AND user_name=? AND source_ip=? AND event_time>=? AND event_time<=?", d.Rule, n.AgentID, n.User, n.SourceIP, stamp(n.EventTime.Add(-correlation.Window)), stamp(n.EventTime.Add(correlation.Window))).Scan(&count); e != nil {
			return e
		}
		if count > 0 {
			return nil
		}
	}
	p, _ := json.Marshal(d)
	_, e := tx.ExecContext(ctx, "INSERT OR IGNORE INTO detections(id,rule,agent_id,user_name,source_ip,event_time,payload) VALUES(?,?,?,?,?,?,?)", d.ID, d.Rule, d.AgentID, d.User, d.SourceIP, stamp(n.EventTime), string(p))
	return e
}
func (s *Store) Run(ctx context.Context, onError func(error)) {
	for {
		if e := s.Step(ctx); e != nil && ctx.Err() == nil {
			onError(e)
		}
		t := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}
