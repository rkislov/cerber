// SPDX-License-Identifier: Apache-2.0
package patch

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"time"
)

type ExecutorConfig struct {
	AgentID   string `json:"agent_id"`
	PublicKey string `json:"public_key"`
	Inbox     string `json:"inbox"`
	Outbox    string `json:"outbox"`
	State     string `json:"state"`
	Manager   string `json:"manager"`
}

func ReadJSON(path string, v any) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 128<<10))
	d.DisallowUnknownFields()
	if e = d.Decode(v); e != nil {
		return e
	}
	var more any
	if d.Decode(&more) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func WriteJSON(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".patch-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0640); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(name, path)
}

// Executor has no network credentials and accepts only signed, expiring requests.
// A committed started marker is never retried automatically after interruption.
func Executor(ctx context.Context, c ExecutorConfig, run func(context.Context, Request) Result, log func(error)) error {
	for _, p := range []string{c.PublicKey, c.Inbox, c.Outbox, c.State} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("executor paths must be absolute")
		}
	}
	if c.Inbox == c.Outbox || c.Manager != "apt" && c.Manager != "dnf" && c.Manager != "wua" {
		return ErrInvalid
	}
	if e := protectedPaths(c.Outbox, filepath.Dir(c.State), c.PublicKey, filepath.Dir(c.PublicKey), filepath.Dir(c.Outbox), filepath.Dir(c.Inbox)); e != nil {
		return e
	}
	if _, e := os.Lstat(c.State); e == nil {
		if e = protectedPaths(c.State); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	key, e := Public(c.PublicKey)
	if e != nil {
		return e
	}
	unlock, e := executorLock(c.State + ".lock")
	if e != nil {
		return e
	}
	defer unlock()
	if e = protectedPaths(c.Outbox, filepath.Dir(c.State), c.PublicKey); e != nil {
		return e
	}
	db, e := sql.Open("sqlite", c.State)
	if e != nil {
		return e
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, e = db.Exec(`PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;CREATE TABLE IF NOT EXISTS executions(id TEXT PRIMARY KEY,request TEXT NOT NULL,result TEXT);`); e != nil {
		return e
	}
	for ctx.Err() == nil {
		entries, e := os.ReadDir(c.Inbox)
		if e != nil {
			return e
		}
		for n, entry := range entries {
			if n >= 100 {
				break
			}
			if ctx.Err() != nil {
				break
			}
			name := entry.Name()
			if len(name) != 37 || filepath.Ext(name) != ".json" {
				continue
			}
			var t Ticket
			if e = ReadJSON(filepath.Join(c.Inbox, name), &t); e != nil {
				log(e)
				continue
			}
			var q Request
			if json.Unmarshal(t.Payload, &q) != nil || q.ID+".json" != name {
				continue
			}
			r, e := processTicket(ctx, db, key, c.AgentID, c.Manager, t, run, time.Now().UTC())
			if e != nil {
				log(e)
				continue
			}
			if e = WriteJSON(filepath.Join(c.Outbox, name), r); e != nil {
				return e
			}
			if e = os.Remove(filepath.Join(c.Inbox, name)); e != nil && !os.IsNotExist(e) {
				return e
			}
		}
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return nil
}

// ProtectExecutorConfig checks deployment permissions before interpreting privileged settings.
func ProtectExecutorConfig(path string) error { return protectedPaths(path, filepath.Dir(path)) }

// processTicket persists authorization before execution and immutable results before delivery.
func processTicket(ctx context.Context, db *sql.DB, key ed25519.PublicKey, agent, manager string, t Ticket, run func(context.Context, Request) Result, now time.Time) (Result, error) {
	var q Request
	if json.Unmarshal(t.Payload, &q) != nil {
		return Result{}, ErrInvalid
	}
	// Verify signature and scope independently of wall-clock expiry for immutable delivery retries.
	if _, e := t.Verify(key, agent, q.ExpiresAt.Add(-time.Nanosecond)); e != nil {
		return Result{}, e
	}
	var stored string
	var prior sql.NullString
	e := db.QueryRow("SELECT request,result FROM executions WHERE id=?", q.ID).Scan(&stored, &prior)
	if e == nil {
		if stored != string(t.Payload) {
			return Result{}, ErrInvalid
		}
		if prior.Valid {
			var r Result
			if json.Unmarshal([]byte(prior.String), &r) != nil {
				return r, ErrInvalid
			}
			return r, nil
		}
	} else if e != sql.ErrNoRows {
		return Result{}, e
	}
	r := unknownResult(q, "interrupted_reconciliation_required")
	if e == sql.ErrNoRows {
		if _, e = db.Exec("INSERT INTO executions(id,request) VALUES(?,?)", q.ID, string(t.Payload)); e != nil {
			return Result{}, e
		}
		if !now.Before(q.ExpiresAt) {
			r = Failure(q, "authorization_expired")
		} else if manager != q.Manager {
			r = Failure(q, "executor_manager_mismatch")
		} else {
			runCtx, cancel := context.WithTimeout(ctx, 90*time.Minute)
			r = run(runCtx, q)
			cancel()
			if r.Validate(q) != nil {
				r = unknownResult(q, "invalid_executor_result")
			}
		}
	}
	b, _ := json.Marshal(r)
	_, e = db.Exec("UPDATE executions SET result=? WHERE id=?", string(b), q.ID)
	return r, e
}
