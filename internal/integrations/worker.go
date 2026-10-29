// SPDX-License-Identifier: Apache-2.0
package integrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/health"
	_ "modernc.org/sqlite"
	"os"
	"strings"
	"sync"
	"time"
)

type Notification struct {
	Sequence          int64
	ID, Subject, Body string
}
type NotificationSource interface {
	NotificationBatch(context.Context, int64) ([]Notification, error)
}
type EventEngine interface {
	NotificationSource
	ScanIOC(context.Context, *Index, string) error
}
type WorkerStatus struct {
	IPs       int    `json:"ips"`
	IPPorts   int    `json:"ip_ports"`
	Domains   int    `json:"domains"`
	URLs      int    `json:"urls"`
	Hashes    int    `json:"hashes"`
	IOCCount  int    `json:"ioc_count"`
	LastFull  string `json:"last_full"`
	SyncError string `json:"sync_error"`
	ScanError string `json:"scan_error"`
	MailError string `json:"mail_error"`
	Pending   int    `json:"pending"`
	Sent      int    `json:"sent"`
	Syncing   bool   `json:"syncing"`
}
type Worker struct {
	settings *Store
	db       *sql.DB
	path     string
	events   EventEngine
	control  NotificationSource
	mu       sync.Mutex
	index    *Index
	revision string
	status   WorkerStatus
	wake     chan struct{}
}

func OpenWorker(settings *Store, path string, events EventEngine, control NotificationSource) (*Worker, error) {
	f, e := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if e != nil {
		return nil, e
	}
	f.Close()
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	_, e = db.Exec(`PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;PRAGMA busy_timeout=5000;CREATE TABLE IF NOT EXISTS feed(id INTEGER PRIMARY KEY CHECK(id=1),revision TEXT NOT NULL,at TEXT NOT NULL,payload TEXT NOT NULL);CREATE TABLE IF NOT EXISTS mail(id TEXT PRIMARY KEY,subject TEXT NOT NULL,body TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,next_at TEXT NOT NULL DEFAULT '',sent_at TEXT);CREATE TABLE IF NOT EXISTS cursors(name TEXT PRIMARY KEY,position INTEGER NOT NULL);`)
	if e != nil {
		db.Close()
		return nil, e
	}
	w := &Worker{settings: settings, db: db, path: path, events: events, control: control, wake: make(chan struct{}, 1)}
	var payload string
	e = db.QueryRow("SELECT revision,at,payload FROM feed WHERE id=1").Scan(&w.revision, &w.status.LastFull, &payload)
	if e == nil {
		var items []IOC
		if json.Unmarshal([]byte(payload), &items) != nil {
			db.Close()
			return nil, fmt.Errorf("invalid persisted ThreatFox feed")
		}
		w.index = NewIndex(items)
		w.status.IOCCount = w.index.Count
	} else if e != sql.ErrNoRows {
		db.Close()
		return nil, e
	}
	return w, nil
}
func (w *Worker) Close() error { return w.db.Close() }
func (w *Worker) Health(ctx context.Context) health.Database {
	return health.CheckDB(ctx, w.db, "Интеграции / очередь почты", w.path)
}
func (w *Worker) Status(ctx context.Context) WorkerStatus {
	w.mu.Lock()
	s := w.status
	index := w.index
	w.mu.Unlock()
	if index != nil {
		ips := map[string]bool{}
		for k, values := range index.Values {
			if strings.HasPrefix(k, "ip_observed:") {
				ips[strings.TrimPrefix(k, "ip_observed:")] = true
			}
			if strings.HasPrefix(k, "ip:") && !strings.HasPrefix(k, "ip:port:") {
				ips[strings.TrimPrefix(k, "ip:")] = true
			}
			if strings.HasPrefix(k, "ip:port:") {
				s.IPPorts += len(values)
			}
			if strings.HasPrefix(k, "domain:") {
				s.Domains += len(values)
			}
			if strings.HasPrefix(k, "url:") {
				s.URLs += len(values)
			}
			if strings.HasPrefix(k, "sha256_hash:") || strings.HasPrefix(k, "md5_hash:") {
				s.Hashes += len(values)
			}
		}
		s.IPs = len(ips)
	}
	w.db.QueryRowContext(ctx, "SELECT count(*) FROM mail WHERE state='pending'").Scan(&s.Pending)
	w.db.QueryRowContext(ctx, "SELECT count(*) FROM mail WHERE state='sent'").Scan(&s.Sent)
	return s
}
func (w *Worker) Sync() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}
func (w *Worker) sync(ctx context.Context) {
	c := w.settings.snapshot()
	if !c.ThreatFoxEnabled || c.ThreatFoxKey == "" {
		return
	}
	w.mu.Lock()
	w.status.Syncing = true
	w.mu.Unlock()
	items, e := downloadFull(ctx, c.ThreatFoxKey)
	revision := ""
	if e == nil {
		b, _ := json.Marshal(items)
		revision = feedID(b)
		_, e = w.db.ExecContext(ctx, "INSERT INTO feed(id,revision,at,payload) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,at=excluded.at,payload=excluded.payload", revision, time.Now().UTC().Format(time.RFC3339), string(b))
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status.Syncing = false
	if e != nil {
		w.status.SyncError = e.Error()
		return
	}
	w.index = NewIndex(items)
	w.revision = revision
	w.status.IOCCount = w.index.Count
	w.status.LastFull = time.Now().UTC().Format(time.RFC3339)
	w.status.SyncError = ""
}
func (w *Worker) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		w.sync(ctx)
		timer := time.NewTicker(time.Hour)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				w.sync(ctx)
			case <-w.wake:
				w.sync(ctx)
			}
		}
	}()
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			w.mail(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	defer wg.Wait()
	for {
		if w.events != nil && w.settings.snapshot().ThreatFoxEnabled {
			w.mu.Lock()
			index, revision := w.index, w.revision
			w.mu.Unlock()
			if index != nil {
				e := w.events.ScanIOC(ctx, index, revision)
				w.mu.Lock()
				w.status.ScanError = ""
				if e != nil {
					w.status.ScanError = "Проверка событий по IOC не выполнена"
				}
				w.mu.Unlock()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (w *Worker) enqueue(ctx context.Context, name string, source NotificationSource) error {
	if source == nil {
		return nil
	}
	var after int64
	e := w.db.QueryRowContext(ctx, "SELECT position FROM cursors WHERE name=?", name).Scan(&after)
	if e != nil && e != sql.ErrNoRows {
		return e
	}
	batch, e := source.NotificationBatch(ctx, after)
	if e != nil {
		return e
	}
	tx, e := w.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, n := range batch {
		if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO mail(id,subject,body) VALUES(?,?,?)", name+":"+n.ID, n.Subject, n.Body); e != nil {
			return e
		}
		after = n.Sequence
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO cursors(name,position) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET position=excluded.position", name, after)
	if e != nil {
		return e
	}
	return tx.Commit()
}

type healthNotificationSource struct {
	engine interface {
		HealthNotificationBatch(context.Context, int64) ([]Notification, error)
	}
}

func (s healthNotificationSource) NotificationBatch(ctx context.Context, after int64) ([]Notification, error) {
	return s.engine.HealthNotificationBatch(ctx, after)
}
func (w *Worker) mail(ctx context.Context) {
	m := w.settings.snapshot().SMTP
	if !m.Enabled {
		return
	}
	e := w.enqueue(ctx, "alerts", w.control)
	if e == nil && w.events != nil {
		e = w.enqueue(ctx, "detections", w.events)
	}
	if e == nil {
		if h, ok := w.events.(interface {
			HealthNotificationBatch(context.Context, int64) ([]Notification, error)
		}); ok {
			e = w.enqueue(ctx, "pipeline-health", healthNotificationSource{h})
		}
	}
	if e == nil {
		for i := 0; i < 10; i++ {
			var id, subject, body string
			var attempts int
			e = w.db.QueryRowContext(ctx, "SELECT id,subject,body,attempts FROM mail WHERE state='pending' AND next_at<=? ORDER BY rowid LIMIT 1", time.Now().UTC().Format(time.RFC3339)).Scan(&id, &subject, &body, &attempts)
			if e == sql.ErrNoRows {
				e = nil
				break
			}
			if e != nil {
				break
			}
			e = sendSMTP(ctx, m, id, subject, body)
			if e != nil {
				delay := time.Minute * time.Duration(1<<min(attempts, 10))
				_, _ = w.db.ExecContext(ctx, "UPDATE mail SET attempts=attempts+1,next_at=? WHERE id=?", time.Now().UTC().Add(delay).Format(time.RFC3339), id)
				break
			}
			_, e = w.db.ExecContext(ctx, "UPDATE mail SET state='sent',sent_at=? WHERE id=?", time.Now().UTC().Format(time.RFC3339), id)
			if e != nil {
				break
			}
		}
	}
	w.mu.Lock()
	w.status.MailError = ""
	if e != nil {
		w.status.MailError = "Письмо не отправлено; очередь сохранена, будет повторная попытка."
	}
	w.mu.Unlock()
}

func (w *Worker) EndpointFeed(ctx context.Context, known string) (string, []IOC, error) {
	var revision, payload string
	e := w.db.QueryRowContext(ctx, "SELECT revision FROM feed WHERE id=1").Scan(&revision)
	if e == nil && revision == known {
		return revision, nil, nil
	}
	if e == nil {
		e = w.db.QueryRowContext(ctx, "SELECT revision,payload FROM feed WHERE id=1").Scan(&revision, &payload)
	}
	if e == sql.ErrNoRows {
		return "", []IOC{}, nil
	}
	if e != nil {
		return "", nil, e
	}
	var items []IOC
	e = json.Unmarshal([]byte(payload), &items)
	return revision, items, e
}

// RulePreviewIndex returns the immutable index snapshot used by the live scanner.
func (w *Worker) RulePreviewIndex() (*Index, string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.index, w.revision
}
