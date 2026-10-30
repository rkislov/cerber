// SPDX-License-Identifier: Apache-2.0
package suricatarules

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"
)

type Config struct {
	Directory string `json:"directory"`
	Binary    string `json:"binary"`
	YAML      string `json:"yaml"`
	Socket    string `json:"socket"`
	PublicKey string `json:"public_key"`
}

func (c Config) Validate() error {
	k, e := base64.StdEncoding.DecodeString(c.PublicKey)
	if e != nil || len(k) != ed25519.PublicKeySize {
		return fmt.Errorf("Suricata signing public key required")
	}
	for _, p := range []string{c.Directory, c.Binary, c.YAML, c.Socket} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fmt.Errorf("absolute clean Suricata paths required")
		}
	}
	if c.Directory == "/" {
		return ErrInvalid
	}
	return nil
}

type saved struct {
	Status  Status    `json:"status"`
	Applied *Manifest `json:"applied,omitempty"`
}
type transaction struct {
	Before  saved `json:"before"`
	Attempt saved `json:"attempt"`
}
type Manager struct {
	config   Config
	engine   Engine
	download func(context.Context, Manifest) ([]byte, error)
	changes  chan Assignment
	mu       sync.Mutex
	saved    saved
}

func NewManager(c Config, engine Engine, download func(context.Context, Manifest) ([]byte, error)) *Manager {
	return &Manager{config: c, engine: engine, download: download, changes: make(chan Assignment, 1), saved: saved{Status: Status{Version: 1, State: "idle", UpdatedAt: time.Now().UTC()}}}
}
func (m *Manager) Snapshot() Status { m.mu.Lock(); defer m.mu.Unlock(); return m.saved.Status }
func (m *Manager) Offer(a Assignment) {
	if a.Revision <= 0 || a.Revision >= 1<<53 || !ValidID(a.Bundle.ID) {
		return
	}
	select {
	case m.changes <- a:
	default:
		select {
		case <-m.changes:
		default:
		}
		select {
		case m.changes <- a:
		default:
		}
	}
}
func (m *Manager) file(s string) string { return filepath.Join(m.config.Directory, s) }
func atomic(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".rules-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (m *Manager) persist(v saved) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return atomic(m.file("state.json"), b)
}
func (m *Manager) set(v saved) {
	v.Status.UpdatedAt = time.Now().UTC()
	m.mu.Lock()
	m.saved = v
	m.mu.Unlock()
}
func (m *Manager) current() saved { m.mu.Lock(); defer m.mu.Unlock(); return m.saved }
func (m *Manager) state(v *saved, state, message string) {
	v.Status.UpdatedAt = time.Now().UTC()
	if len(message) > 500 {
		message = message[:500]
	}
	v.Status.State = state
	v.Status.Error = message
	m.set(*v)
}
func readBounded(path string, limit int) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > int64(limit) {
		return nil, ErrInvalid
	}
	b := make([]byte, info.Size())
	_, e = io.ReadFull(f, b)
	return b, e
}
func (m *Manager) Run(ctx context.Context) {
	if e := m.initialize(ctx); e != nil {
		v := m.current()
		m.state(&v, "error", e.Error())
	}
	for {
		select {
		case <-ctx.Done():
			return
		case a := <-m.changes:
			if a.Revision > m.Snapshot().Revision {
				m.apply(ctx, a)
			}
		}
	}
}
func (m *Manager) initialize(ctx context.Context) error {
	if e := m.config.Validate(); e != nil {
		return e
	}
	if e := os.MkdirAll(m.config.Directory, 0700); e != nil {
		return e
	}
	if b, e := readBounded(m.file("state.json"), 16384); e == nil {
		var v saved
		if json.Unmarshal(b, &v) != nil || v.Status.Validate() != nil || v.Applied != nil && v.Applied.Verify(m.config.PublicKey) != nil {
			return fmt.Errorf("invalid persisted Suricata state")
		}
		m.set(v)
	} else if !os.IsNotExist(e) {
		return e
	}
	if b, e := readBounded(m.file("transaction.json"), 32768); e == nil {
		var t transaction
		if json.Unmarshal(b, &t) != nil {
			return ErrInvalid
		}
		if e = m.restore(t); e != nil {
			return e
		}
		v := t.Attempt
		v.Applied = t.Before.Applied
		v.Status.AppliedID = t.Before.Status.AppliedID
		m.state(&v, "error", "Interrupted activation recovered; assign again to retry")
		if e = m.persist(v); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	major, e := m.engine.Major(ctx)
	v := m.current()
	v.Status.EngineMajor = major
	m.set(v)
	if e != nil {
		return e
	}
	// Re-confirm persisted activation after restart, including the running engine.
	if v.Applied != nil {
		phase, message := v.Status.State, v.Status.Error
		m.state(&v, "testing", "")
		if e = m.engine.Test(ctx, m.file("active.rules")); e != nil {
			return e
		}
		m.state(&v, "reloading", "")
		if e = m.engine.Reload(ctx, v.Applied.Count); e != nil {
			return e
		}
		m.state(&v, phase, message)
	}
	return nil
}
func (m *Manager) restore(t transaction) error {
	b, e := readBounded(m.file("previous.rules"), MaxRules)
	if e != nil {
		return fmt.Errorf("rollback file unavailable")
	}
	if e = atomic(m.file("active.rules"), b); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	count := 0
	if t.Before.Applied != nil {
		count = t.Before.Applied.Count
	} else {
		_, count, _ = Normalize(b)
	}
	if e = m.engine.Reload(ctx, count); e != nil {
		return fmt.Errorf("rollback reload failed; local recovery required")
	}
	if e = m.persist(t.Before); e != nil {
		return e
	}
	return os.Remove(m.file("transaction.json"))
}
func (m *Manager) apply(parent context.Context, a Assignment) {
	before := m.current()
	v := before
	v.Status.Revision = a.Revision
	v.Status.DesiredID = a.Bundle.ID
	fail := func(e error) { m.state(&v, "error", e.Error()); _ = m.persist(v) }
	// A failed rollback is a hard stop. Never overwrite its recovery journal.
	if _, e := os.Stat(m.file("transaction.json")); e == nil {
		m.state(&v, "rollback_failed", "Unresolved activation journal; restart sensor after restoring engine access")
		return
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Minute)
	defer cancel()
	major, e := m.engine.Major(ctx)
	v.Status.EngineMajor = major
	if e != nil {
		fail(e)
		return
	}
	if major != a.Bundle.EngineMajor || a.Bundle.Verify(m.config.PublicKey) != nil {
		fail(fmt.Errorf("engine version or package signature mismatch"))
		return
	}
	m.state(&v, "downloading", "")
	data, e := m.download(ctx, a.Bundle)
	if e != nil {
		fail(e)
		return
	}
	plain, e := Unpack(a.Bundle, data)
	if e != nil {
		fail(fmt.Errorf("package checksum/content verification failed"))
		return
	}
	candidate := m.file("candidate.rules")
	if e = atomic(candidate, plain); e != nil {
		fail(e)
		return
	}
	defer os.Remove(candidate)
	large := len(plain) > 4<<20
	plain = nil
	data = nil
	// Release decompression/parser buffers before a second Suricata process
	// validates a large ruleset in the same memory-limited service/container.
	if large {
		debug.FreeOSMemory()
	}
	m.state(&v, "testing", "")
	if e = m.engine.Test(ctx, candidate); e != nil {
		fail(e)
		return
	}
	old, e := readBounded(m.file("active.rules"), MaxRules)
	if os.IsNotExist(e) {
		old = []byte("# Initial empty managed ruleset\n")
		e = nil
	}
	if e != nil {
		fail(e)
		return
	}
	if e = atomic(m.file("previous.rules"), old); e != nil {
		fail(e)
		return
	}
	t := transaction{Before: before, Attempt: v}
	journal, _ := json.Marshal(t)
	if e = atomic(m.file("transaction.json"), journal); e != nil {
		fail(e)
		return
	}
	m.state(&v, "reloading", "")
	if e = os.Rename(candidate, m.file("active.rules")); e == nil {
		d, err := os.Open(m.config.Directory)
		if err == nil {
			err = d.Sync()
			_ = d.Close()
		}
		e = err
		if e == nil {
			e = m.engine.Reload(ctx, a.Bundle.Count)
		}
	}
	if e != nil {
		original := e
		if e = m.restore(t); e != nil {
			m.state(&v, "rollback_failed", e.Error())
			return
		}
		fail(fmt.Errorf("activation failed; previous rules restored: %v", original))
		return
	}
	v.Applied = &a.Bundle
	v.Status.AppliedID = a.Bundle.ID
	v.Status.State = "applied"
	v.Status.Error = ""
	v.Status.UpdatedAt = time.Now().UTC()
	if e = m.persist(v); e != nil {
		if re := m.restore(t); re != nil {
			m.state(&v, "rollback_failed", re.Error())
			return
		}
		v = before
		v.Status.Revision = a.Revision
		v.Status.DesiredID = a.Bundle.ID
		fail(fmt.Errorf("activation state could not be saved; previous rules restored"))
		return
	}
	if e = os.Remove(m.file("transaction.json")); e != nil {
		m.state(&v, "rollback_failed", "Cannot finalize activation journal; restart sensor to recover")
		return
	}
	m.set(v)
	_ = os.Remove(m.file("previous.rules"))
}
