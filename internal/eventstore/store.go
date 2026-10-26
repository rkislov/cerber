// SPDX-License-Identifier: Apache-2.0
// Package eventstore is the SQLite event-journal adapter for small installations.
// It deliberately uses a separate database from inventory/control-plane data.
package eventstore

import (
	"bytes"
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rkislov/cerber/internal/correlation"
	"github.com/rkislov/cerber/internal/telemetry"
	_ "modernc.org/sqlite"
)

//go:embed incidents.sql
var incidentsSchema string

//go:embed lifecycle.sql
var lifecycleSchema string

type Store struct {
	healthMu                               sync.Mutex
	lastHealth                             telemetry.PipelineHealth
	lastHealthOrdinal, lastHealthProcessed int64
	path                                   string
	db                                     *sql.DB
	lifecycleMu                            sync.Mutex
	archiveDir                             string
	archiveConfigMu                        sync.RWMutex
}

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
	s := &Store{db: db, path: path}
	for _, q := range []string{"PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL"} {
		if _, e = db.ExecContext(ctx, q); e != nil {
			db.Close()
			return nil, e
		}
	}
	var version int
	if e = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); e != nil || version > 4 {
		db.Close()
		return nil, fmt.Errorf("unsupported event database version: %d: %v", version, e)
	}
	if version < 2 {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			db.Close()
			return nil, err
		}
		if version == 0 {
			_, err = tx.ExecContext(ctx, schema)
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, incidentsSchema)
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, "PRAGMA user_version=2")
		}
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		if err != nil {
			db.Close()
			return nil, err
		}
	}
	if version < 3 {
		if _, e = db.ExecContext(ctx, "BEGIN;"+lifecycleSchema+"PRAGMA user_version=3;COMMIT;"); e != nil {
			db.ExecContext(ctx, "ROLLBACK")
			db.Close()
			return nil, e
		}
	}
	if version < 4 {
		if _, e = db.ExecContext(ctx, `BEGIN;ALTER TABLE event_retention ADD COLUMN max_bytes INTEGER NOT NULL DEFAULT 1073741824;CREATE TABLE IF NOT EXISTS pipeline_health_alerts(id TEXT PRIMARY KEY,kind TEXT NOT NULL,severity TEXT NOT NULL,detail TEXT NOT NULL,raised_at TEXT NOT NULL,resolved_at TEXT);CREATE UNIQUE INDEX IF NOT EXISTS pipeline_health_active ON pipeline_health_alerts(kind) WHERE resolved_at IS NULL;CREATE TABLE IF NOT EXISTS pipeline_health_notifications(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL,subject TEXT NOT NULL,body TEXT NOT NULL);PRAGMA user_version=4;COMMIT;`); e != nil {
			db.ExecContext(ctx, "ROLLBACK")
			db.Close()
			return nil, e
		}
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
	var maxBytes int64
	if e = tx.QueryRowContext(ctx, "SELECT max_bytes FROM event_retention WHERE id=1").Scan(&maxBytes); e != nil {
		return receipt, e
	}
	initialBytes := rawBytes
	for _, r := range b.Records {
		id := telemetry.ID(agent, r.ID)
		p, _ := json.Marshal(r)
		var stored string
		e = tx.QueryRowContext(ctx, "SELECT payload FROM raw_events WHERE id=? OR (agent_id=? AND source=? AND cursor=?)", id, agent, r.Source, r.Cursor).Scan(&stored)
		if e == nil {
			// A source reread after deliberate spool recovery has a new observation
			// time. Keep the first observation; identity, cursor and source data stay immutable.
			var previous telemetry.Raw
			if json.Unmarshal([]byte(stored), &previous) != nil {
				return receipt, telemetry.ErrConflict
			}
			if previous.ID != r.ID || previous.Source != r.Source || previous.Cursor != r.Cursor || !equivalentSourceJSON(previous.Data, r.Data) {
				return receipt, telemetry.ErrConflict
			}
			continue
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return receipt, e
		}
		var oldID, oldDigest string
		e = tx.QueryRowContext(ctx, "SELECT id,digest FROM retired_events WHERE id=? OR (agent_id=? AND source=? AND cursor=?)", id, agent, r.Source, r.Cursor).Scan(&oldID, &oldDigest)
		if e == nil {
			digest, err := sourceDigest(r)
			if err != nil || oldID != id || digest != oldDigest {
				return receipt, telemetry.ErrConflict
			}
			continue
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return receipt, e
		}
		rawBytes += int64(len(p))
		if rawBytes > maxBytes {
			return receipt, telemetry.ErrFull
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO raw_events(id,agent_id,asset_id,source,cursor,received_at,payload) VALUES(?,?,?,?,?,?,?)", id, agent, asset, r.Source, r.Cursor, stamp(now), string(p)); e != nil {
			return receipt, e
		}
	}
	receipt = telemetry.Receipt{BatchID: b.ID, AgentID: agent, Count: len(b.Records), ReceivedAt: now}
	p, _ := json.Marshal(receipt)
	rawBytes += int64(len(p)) + 256
	if rawBytes > maxBytes {
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
	if e = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(length(CAST(payload AS BLOB))),0) FROM event_spool").Scan(&count, &size); e != nil {
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
	if n.Class == "firewall" || n.Class == "fess" {
		rows, err := tx.QueryContext(ctx, `SELECT payload FROM normalized_events WHERE class=? AND status='parsed' AND ((?='syn' AND json_extract(payload,'$.action')='syn') OR (?<>'syn' AND outcome='failure')) AND agent_id=? AND source_ip=? AND json_extract(payload,'$.product')=? AND coalesce(json_extract(payload,'$.device'),'')=? AND coalesce(json_extract(payload,'$.destination_ip'),'')=? AND event_time>=? AND event_time<=? AND sequence<=? ORDER BY event_time DESC,sequence DESC LIMIT 100`, n.Class, n.Action, n.Action, n.AgentID, n.SourceIP, n.Product, n.Device, n.DestinationIP, stamp(n.EventTime.Add(-correlation.Window)), stamp(n.EventTime), n.Sequence)
		if err != nil {
			return err
		}
		for rows.Next() {
			var p string
			var f telemetry.Normalized
			if err = rows.Scan(&p); err != nil {
				rows.Close()
				return err
			}
			if err = json.Unmarshal([]byte(p), &f); err != nil {
				rows.Close()
				return err
			}
			failures = append(failures, f)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	d := correlation.Evaluate(n, failures)
	if n.Class == "firewall" || n.Class == "fess" {
		d = correlation.Network(n, failures)
	}
	if d == nil {
		return nil
	}
	if d.Rule == "auth.repeated_failures" || n.Class == "firewall" || n.Class == "fess" {
		var count int
		if e := tx.QueryRowContext(ctx, "SELECT count(*) FROM detections WHERE rule=? AND agent_id=? AND user_name=? AND source_ip=? AND coalesce(json_extract(payload,'$.group_key'),'')=? AND event_time>=? AND event_time<=?", d.Rule, n.AgentID, d.User, n.SourceIP, d.GroupKey, stamp(n.EventTime.Add(-correlation.Window)), stamp(n.EventTime.Add(correlation.Window))).Scan(&count); e != nil {
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
	healthDone := make(chan struct{})
	go func() {
		defer close(healthDone)
		for {
			if e := s.SamplePipelineHealth(ctx, time.Now().UTC()); e != nil && ctx.Err() == nil {
				onError(e)
			}
			timer := time.NewTimer(30 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	defer func() { <-healthDone }()

	maintenanceDone := make(chan struct{})
	go func() {
		defer close(maintenanceDone)
		for {
			if _, e := s.Maintain(ctx, time.Now().UTC()); e != nil && ctx.Err() == nil {
				onError(e)
			}
			t := time.NewTimer(time.Minute)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
	}()
	defer func() { <-maintenanceDone }()

	for {
		delay, err := s.stepAndDelay(ctx)
		if err != nil && ctx.Err() == nil {
			onError(err)
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// stepAndDelay keeps work bounded and makes idle/backlog scheduling independent
// of the wall-clock speed of SQLite or the host running the service.
func (s *Store) stepAndDelay(ctx context.Context) (time.Duration, error) {
	if e := s.Step(ctx); e != nil {
		return time.Second, e
	}
	var pending bool
	e := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM raw_events WHERE sequence>(SELECT position FROM consumer_cursors WHERE name='normalizer/1')) OR EXISTS(SELECT 1 FROM normalized_events WHERE sequence>(SELECT position FROM consumer_cursors WHERE name='correlator/1'))`).Scan(&pending)
	if e != nil {
		return time.Second, e
	}
	if pending {
		return 10 * time.Millisecond, nil
	}
	return time.Second, nil
}

// JSON field order is not part of a native event's identity. UseNumber preserves
// large integers while comparing structured records; the original first payload stays intact.
func equivalentSourceJSON(a, b json.RawMessage) bool {
	canonical := func(p json.RawMessage) ([]byte, error) {
		d := json.NewDecoder(bytes.NewReader(p))
		d.UseNumber()
		var v any
		if e := d.Decode(&v); e != nil {
			return nil, e
		}
		return json.Marshal(v)
	}
	x, e := canonical(a)
	if e != nil {
		return false
	}
	y, e := canonical(b)
	return e == nil && bytes.Equal(x, y)
}

func (s *Store) EventQueueUsage(ctx context.Context, agent string) (int64, int64, error) {
	var count, size int64
	e := s.db.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(length(CAST(payload AS BLOB))),0) FROM event_spool WHERE agent_id=?", agent).Scan(&count, &size)
	return count, size, e
}

func sourceDigest(r telemetry.Raw) (string, error) {
	var v any
	d := json.NewDecoder(bytes.NewReader(r.Data))
	d.UseNumber()
	if e := d.Decode(&v); e != nil {
		return "", e
	}
	b, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	return telemetry.ID(r.ID, r.Source, r.Cursor, string(b)), nil
}
