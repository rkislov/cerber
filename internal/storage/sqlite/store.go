// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/event"
	"github.com/rkislov/cerber/internal/ports"
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

type Store struct{ db *sql.DB }

var _ ports.Repository = (*Store)(nil)
var _ ports.EventReader = (*Store)(nil)

func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// One connection serializes local writers and keeps PRAGMAs consistent.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err = s.init(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) init(ctx context.Context) error {
	for _, q := range []string{"PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL"} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	switch version {
	case 0:
		if _, err = tx.ExecContext(ctx, schema); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "PRAGMA user_version=2"); err != nil {
			return err
		}
	case 1:
		if _, err = tx.ExecContext(ctx, "ALTER TABLE tasks ADD COLUMN knowledge_snapshot TEXT CHECK(knowledge_snapshot IS NULL OR json_valid(knowledge_snapshot))"); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "PRAGMA user_version=2"); err != nil {
			return err
		}
	case 2:
	default:
		return fmt.Errorf("unsupported database schema version %d", version)
	}
	return tx.Commit()
}
func stamp(t time.Time) string          { return t.UTC().Format("2006-01-02T15:04:05.000000000Z") }
func parse(s string) (time.Time, error) { return time.Parse(time.RFC3339Nano, s) }
func appendEvent(ctx context.Context, tx *sql.Tx, e event.Envelope) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO outbox(id,schema_version,kind,aggregate_id,source,occurred_at,payload) VALUES(?,?,?,?,?,?,?)`,
		e.ID, e.SchemaVersion, e.Kind, e.AggregateID, e.Source, stamp(e.OccurredAt), string(e.Payload))
	return err
}
func (s *Store) mutate(ctx context.Context, e event.Envelope, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = fn(tx); err != nil {
		return err
	}
	if err = appendEvent(ctx, tx, e); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) CreateAsset(ctx context.Context, a domain.Asset, e event.Envelope) error {
	return s.mutate(ctx, e, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO assets VALUES(?,?,?,?)", a.ID, a.IP, a.Name, stamp(a.CreatedAt))
		return err
	})
}
func (s *Store) Assets(ctx context.Context) ([]domain.Asset, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,ip,name,created_at FROM assets ORDER BY ip")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []domain.Asset{}
	for rows.Next() {
		var a domain.Asset
		var at string
		if err = rows.Scan(&a.ID, &a.IP, &a.Name, &at); err != nil {
			return nil, err
		}
		a.CreatedAt, err = parse(at)
		if err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	return result, rows.Err()
}
func (s *Store) CreateTarget(ctx context.Context, t domain.Target, e event.Envelope) error {
	return s.mutate(ctx, e, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT INTO targets VALUES(?,?,?)", t.ID, t.Name, stamp(t.CreatedAt)); err != nil {
			return err
		}
		for _, id := range t.AssetIDs {
			if _, err := tx.ExecContext(ctx, "INSERT INTO target_assets VALUES(?,?)", t.ID, id); err != nil {
				return err
			}
		}
		return nil
	})
}
func (s *Store) Targets(ctx context.Context) ([]domain.Target, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT t.id,t.name,t.created_at,a.asset_id FROM targets t JOIN target_assets a ON a.target_id=t.id ORDER BY t.id,a.asset_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []domain.Target{}
	for rows.Next() {
		var id, name, at, asset string
		if err = rows.Scan(&id, &name, &at, &asset); err != nil {
			return nil, err
		}
		if len(result) == 0 || result[len(result)-1].ID != id {
			created, err := parse(at)
			if err != nil {
				return nil, err
			}
			result = append(result, domain.Target{ID: id, Name: name, CreatedAt: created, AssetIDs: []string{}})
		}
		result[len(result)-1].AssetIDs = append(result[len(result)-1].AssetIDs, asset)
	}
	return result, rows.Err()
}
func (s *Store) TargetHosts(ctx context.Context, id string) ([]domain.Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.id,a.ip FROM assets a JOIN target_assets t ON a.id=t.asset_id WHERE t.target_id=? ORDER BY a.id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hosts := []domain.Host{}
	for rows.Next() {
		var h domain.Host
		if err = rows.Scan(&h.AssetID, &h.IP); err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, domain.ErrNotFound
	}
	return hosts, nil
}
func (s *Store) CreateTask(ctx context.Context, t domain.Task, e event.Envelope) error {
	hosts, err := json.Marshal(t.Hosts)
	if err != nil {
		return err
	}
	config, err := json.Marshal(t.Config)
	if err != nil {
		return err
	}
	return s.mutate(ctx, e, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO tasks(id,target_id,hosts,config,status,created_at) VALUES(?,?,?,?,?,?)`, t.ID, t.TargetID, string(hosts), string(config), t.Status, stamp(t.CreatedAt))
		return err
	})
}

const taskColumns = "id,target_id,hosts,config,status,created_at,started_at,finished_at,error,knowledge_snapshot"

type rowScanner interface{ Scan(...any) error }

func readTask(row rowScanner) (domain.Task, error) {
	var t domain.Task
	var hosts, config, at string
	var started, finished, knowledge sql.NullString
	err := row.Scan(&t.ID, &t.TargetID, &hosts, &config, &t.Status, &at, &started, &finished, &t.Error, &knowledge)
	if errors.Is(err, sql.ErrNoRows) {
		return t, domain.ErrNotFound
	}
	if err != nil {
		return t, err
	}
	if err = json.Unmarshal([]byte(hosts), &t.Hosts); err != nil {
		return t, err
	}
	if err = json.Unmarshal([]byte(config), &t.Config); err != nil {
		return t, err
	}
	if knowledge.Valid {
		var snapshot domain.KnowledgeSnapshot
		if err = json.Unmarshal([]byte(knowledge.String), &snapshot); err != nil {
			return t, err
		}
		t.Knowledge = &snapshot
	}
	if t.CreatedAt, err = parse(at); err != nil {
		return t, err
	}
	if started.Valid {
		v, e := parse(started.String)
		if e != nil {
			return t, e
		}
		t.StartedAt = &v
	}
	if finished.Valid {
		v, e := parse(finished.String)
		if e != nil {
			return t, e
		}
		t.FinishedAt = &v
	}
	return t, nil
}
func (s *Store) Task(ctx context.Context, id string) (domain.Task, error) {
	return readTask(s.db.QueryRowContext(ctx, "SELECT "+taskColumns+" FROM tasks WHERE id=?", id))
}
func (s *Store) Tasks(ctx context.Context) ([]domain.Task, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+taskColumns+" FROM tasks ORDER BY created_at,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tasks := []domain.Task{}
	for rows.Next() {
		t, err := readTask(rows)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}
func changed(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return domain.ErrConflict
	}
	return nil
}
func (s *Store) ClaimTask(ctx context.Context, id string, snapshot *domain.KnowledgeSnapshot, e event.Envelope) error {
	var knowledge any
	if snapshot != nil {
		if err := snapshot.Validate(); err != nil {
			return err
		}
		data, err := json.Marshal(snapshot)
		if err != nil {
			return err
		}
		knowledge = string(data)
	}
	return s.mutate(ctx, e, func(tx *sql.Tx) error {
		return changed(tx.ExecContext(ctx, `UPDATE tasks SET status='running',started_at=?,knowledge_snapshot=? WHERE id=? AND status='queued'`, stamp(e.OccurredAt), knowledge, id))
	})
}
func (s *Store) RecordObservation(ctx context.Context, o domain.Observation, e event.Envelope) error {
	return s.mutate(ctx, e, func(tx *sql.Tx) error {
		var status string
		if err := tx.QueryRowContext(ctx, "SELECT status FROM tasks WHERE id=?", o.TaskID).Scan(&status); err != nil {
			return err
		}
		if status != string(domain.Running) {
			return domain.ErrConflict
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO observations VALUES(?,?,?,?,?,?,?,?)`, o.TaskID, o.AssetID, o.IP, o.Port, o.Protocol, o.State, o.Detail, stamp(o.ObservedAt))
		return err
	})
}
func (s *Store) FinishTask(ctx context.Context, id string, status domain.TaskStatus, detail string, e event.Envelope) error {
	if status != domain.Completed && status != domain.Failed && status != domain.Interrupted {
		return fmt.Errorf("invalid terminal status")
	}
	return s.mutate(ctx, e, func(tx *sql.Tx) error {
		return changed(tx.ExecContext(ctx, `UPDATE tasks SET status=?,finished_at=?,error=? WHERE id=? AND status='running'`, status, stamp(e.OccurredAt), detail, id))
	})
}
func (s *Store) Observations(ctx context.Context, id string) ([]domain.Observation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT task_id,asset_id,ip,port,protocol,state,detail,observed_at FROM observations WHERE task_id=? ORDER BY asset_id,port`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []domain.Observation{}
	for rows.Next() {
		var o domain.Observation
		var at string
		if err = rows.Scan(&o.TaskID, &o.AssetID, &o.IP, &o.Port, &o.Protocol, &o.State, &o.Detail, &at); err != nil {
			return nil, err
		}
		o.ObservedAt, err = parse(at)
		if err != nil {
			return nil, err
		}
		result = append(result, o)
	}
	return result, rows.Err()
}
func (s *Store) Events(ctx context.Context, after int64, limit int) ([]event.Envelope, error) {
	if after < 0 || limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("invalid event cursor or limit (1–1000)")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT sequence,id,schema_version,kind,aggregate_id,source,occurred_at,payload FROM outbox WHERE sequence>? ORDER BY sequence LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []event.Envelope{}
	for rows.Next() {
		var e event.Envelope
		var at, payload string
		if err = rows.Scan(&e.Sequence, &e.ID, &e.SchemaVersion, &e.Kind, &e.AggregateID, &e.Source, &at, &payload); err != nil {
			return nil, err
		}
		e.OccurredAt, err = parse(at)
		if err != nil {
			return nil, err
		}
		e.Payload = json.RawMessage(payload)
		result = append(result, e)
	}
	return result, rows.Err()
}
