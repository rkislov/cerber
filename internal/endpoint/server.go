// SPDX-License-Identifier: Apache-2.0
package endpoint

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/integrations"
	"github.com/rkislov/cerber/internal/telemetry"
	_ "modernc.org/sqlite"
	"net/netip"
	"os"
	"sync"
	"time"
)

type Feed interface {
	EndpointFeed(context.Context, string) (string, []integrations.IOC, error)
}
type Receiver interface {
	AgentBinding(context.Context, string, string) (string, error)
}
type EventSink interface {
	Accept(context.Context, string, string, telemetry.Batch) (telemetry.Receipt, error)
}
type Server struct {
	db     *sql.DB
	key    ed25519.PrivateKey
	feed   Feed
	events EventSink
	mu     sync.Mutex
}
type Command struct {
	Action  string `json:"action"`
	Policy  Policy `json:"policy"`
	ID      string `json:"id"`
	Agent   string `json:"agent"`
	IP      string `json:"ip"`
	Minutes int    `json:"minutes"`
	Reason  string `json:"reason"`
	Confirm bool   `json:"confirm"`
}

func Open(path string, key ed25519.PrivateKey, feed Feed, events EventSink) (*Server, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	f.Close()
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	_, e = db.Exec(`PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;PRAGMA busy_timeout=5000;CREATE TABLE IF NOT EXISTS policies(id TEXT PRIMARY KEY,payload TEXT NOT NULL);CREATE TABLE IF NOT EXISTS assignments(agent TEXT PRIMARY KEY,policy TEXT NOT NULL);CREATE TABLE IF NOT EXISTS blocks(id TEXT PRIMARY KEY,agent TEXT NOT NULL,payload TEXT NOT NULL);CREATE TABLE IF NOT EXISTS reports(agent TEXT PRIMARY KEY,payload TEXT NOT NULL);CREATE TABLE IF NOT EXISTS audit(sequence INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,payload TEXT NOT NULL);`)
	if e != nil {
		db.Close()
		return nil, e
	}
	return &Server{db: db, key: key, feed: feed, events: events}, nil
}
func (s *Server) Close() error { return s.db.Close() }
func defaultPolicy() Policy {
	return Policy{ID: "default", Name: "Без политики", Class: "server", Version: 1, Mode: "off", ScanIntervalMinutes: 1440, ScanHourUTC: 0, SyncMinutes: 60, Exclude: []string{}, Protected: []string{}, Agents: []string{}}
}
func (s *Server) policy(ctx context.Context, agent string) (Policy, error) {
	var p string
	e := s.db.QueryRowContext(ctx, "SELECT p.payload FROM assignments a JOIN policies p ON p.id=a.policy WHERE a.agent=?", agent).Scan(&p)
	if e == sql.ErrNoRows {
		return defaultPolicy(), nil
	}
	if e != nil {
		return Policy{}, e
	}
	var v Policy
	e = json.Unmarshal([]byte(p), &v)
	return v, e
}
func (s *Server) Command(ctx context.Context, c Command, actor string, protected []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if actor == "" || len(actor) > 64 {
		return ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	switch c.Action {
	case "policy":
		if !c.Confirm || c.Policy.Validate() != nil {
			return ErrInvalid
		}
		p := c.Policy
		if p.ID == "" {
			p.ID = telemetry.ID(actor, p.Name, now.String())[:32]
			p.Version = 0
		}
		var old string
		e = tx.QueryRowContext(ctx, "SELECT payload FROM policies WHERE id=?", p.ID).Scan(&old)
		if e != nil && e != sql.ErrNoRows {
			return e
		}
		if e == nil {
			var previous Policy
			if json.Unmarshal([]byte(old), &previous) != nil || p.Version != previous.Version {
				return ErrInvalid
			}
		} else if p.Version != 0 {
			return ErrInvalid
		}
		p.Version++
		b, _ := json.Marshal(p)
		if _, e = tx.ExecContext(ctx, "INSERT INTO policies VALUES(?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", p.ID, string(b)); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM assignments WHERE policy=?", p.ID); e != nil {
			return e
		}
		for _, agent := range p.Agents {
			if !telemetry.AgentIdentifier(agent) {
				return ErrInvalid
			}
			var assigned string
			e = tx.QueryRowContext(ctx, "SELECT policy FROM assignments WHERE agent=?", agent).Scan(&assigned)
			if e != nil && e != sql.ErrNoRows {
				return e
			}
			if e == nil && assigned != p.ID {
				return fmt.Errorf("agent already assigned; remove it from the old policy first")
			}
			if _, e = tx.ExecContext(ctx, "INSERT INTO assignments VALUES(?,?) ON CONFLICT(agent) DO UPDATE SET policy=excluded.policy", agent, p.ID); e != nil {
				return e
			}
		}
		c.Policy = p
	case "block":
		var active int
		if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM blocks WHERE agent=? AND json_extract(payload,'$.state')='active' AND json_extract(payload,'$.expires')>?", c.Agent, now.Format(time.RFC3339Nano)).Scan(&active); e != nil {
			return e
		}
		if active >= 100 {
			return ErrInvalid
		}
		if !c.Confirm || !telemetry.AgentIdentifier(c.Agent) || c.Minutes < 1 || c.Minutes > 1440 || len(c.Reason) < 5 || len(c.Reason) > 1000 {
			return ErrInvalid
		}
		ip, e := netip.ParseAddr(c.IP)
		if e != nil {
			return ErrInvalid
		}
		ip = ip.Unmap()
		if ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() {
			return ErrInvalid
		}
		var text string
		e = tx.QueryRowContext(ctx, "SELECT p.payload FROM assignments a JOIN policies p ON p.id=a.policy WHERE a.agent=?", c.Agent).Scan(&text)
		if e != nil {
			return ErrInvalid
		}
		var p Policy
		if json.Unmarshal([]byte(text), &p) != nil || p.Mode == "off" {
			return ErrInvalid
		}
		for _, value := range append(append([]string{}, protected...), p.Protected...) {
			if a, e := netip.ParseAddr(value); e == nil && a.Unmap() == ip {
				return ErrInvalid
			}
			if prefix, e := netip.ParsePrefix(value); e == nil && prefix.Contains(ip) {
				return ErrInvalid
			}
		}
		state := "active"
		if p.Mode == "learning" {
			state = "learning"
		}
		b := Block{ID: telemetry.ID(actor, c.Agent, ip.String(), now.String())[:32], Agent: c.Agent, IP: ip.String(), Created: now, Expires: now.Add(time.Duration(c.Minutes) * time.Minute), Actor: actor, Reason: c.Reason, State: state}
		data, _ := json.Marshal(b)
		if _, e = tx.ExecContext(ctx, "INSERT INTO blocks VALUES(?,?,?)", b.ID, b.Agent, string(data)); e != nil {
			return e
		}
		c.ID = b.ID
	case "cancel":
		var data string
		if e = tx.QueryRowContext(ctx, "SELECT payload FROM blocks WHERE id=?", c.ID).Scan(&data); e != nil {
			return e
		}
		var b Block
		if json.Unmarshal([]byte(data), &b) != nil {
			return ErrInvalid
		}
		b.State = "cancelled"
		dataBytes, _ := json.Marshal(b)
		if _, e = tx.ExecContext(ctx, "UPDATE blocks SET payload=? WHERE id=?", string(dataBytes), c.ID); e != nil {
			return e
		}
	default:
		return ErrInvalid
	}
	data, _ := json.Marshal(c)
	if _, e = tx.ExecContext(ctx, "INSERT INTO audit(at,actor,action,payload) VALUES(?,?,?,?)", now.Format(time.RFC3339), actor, c.Action, string(data)); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Server) View(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	for _, table := range []string{"policies", "blocks", "reports", "audit"} {
		query := "SELECT payload FROM " + table
		if table == "audit" {
			query = "SELECT json_object('at',at,'actor',actor,'action',action,'command',json(payload)) FROM audit ORDER BY sequence DESC LIMIT 100"
		} else if table == "blocks" {
			query += " ORDER BY rowid DESC LIMIT 100"
		} else if table == "reports" {
			query = "SELECT json_object('agent',agent,'report',json(payload)) FROM reports"
		}
		rows, e := s.db.QueryContext(ctx, query)
		if e != nil {
			return nil, e
		}
		values := []json.RawMessage{}
		for rows.Next() {
			var p string
			if e = rows.Scan(&p); e != nil {
				rows.Close()
				return nil, e
			}
			values = append(values, json.RawMessage(p))
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
		out[table] = values
	}
	return out, nil
}
func (s *Server) Exchange(ctx context.Context, agent, asset string, report Report) (Signed, error) {
	if len(report.Findings) > 100 || len(report.Blocks) > 100 || len(report.Error) > 2000 {
		return Signed{}, ErrInvalid
	}
	if len(report.Findings) > 0 && s.events != nil {
		batch := telemetry.Batch{SchemaVersion: 1, AgentID: agent}
		for _, f := range report.Findings {
			if !telemetry.Identifier(f.ID) || len(f.Path) > 4096 || len(f.SHA256) != 64 || len(f.MD5) != 32 || f.At.IsZero() {
				return Signed{}, ErrInvalid
			}
			data, _ := json.Marshal(f)
			batch.Records = append(batch.Records, telemetry.Raw{ID: f.ID, Source: "agent:ioc", Cursor: f.ID, ObservedAt: f.At, Data: data})
		}
		batch.ID = telemetry.ID(agent, string(mustJSON(batch.Records)))
		if _, e := s.events.Accept(ctx, agent, asset, batch); e != nil {
			return Signed{}, e
		}
	}
	var previousJSON string
	if e := s.db.QueryRowContext(ctx, "SELECT payload FROM reports WHERE agent=?", agent).Scan(&previousJSON); e == nil {
		var previous Report
		if json.Unmarshal([]byte(previousJSON), &previous) == nil {
			if report.Blocks == nil {
				report.Blocks = map[string]string{}
			}
			for id, state := range previous.Blocks {
				if len(report.Blocks) >= 100 {
					break
				}
				if _, ok := report.Blocks[id]; !ok {
					report.Blocks[id] = state
				}
			}
		}
	}
	data, _ := json.Marshal(report)
	if _, e := s.db.ExecContext(ctx, "INSERT INTO reports VALUES(?,?) ON CONFLICT(agent) DO UPDATE SET payload=excluded.payload", agent, string(data)); e != nil {
		return Signed{}, e
	}
	p, e := s.policy(ctx, agent)
	if e != nil {
		return Signed{}, e
	}
	bundle := Bundle{Agent: agent, Issued: time.Now().UTC(), Expires: time.Now().UTC().Add(24 * time.Hour), Policy: p, Blocks: []Block{}}
	if p.Mode == "confirm" {
		rows, e := s.db.QueryContext(ctx, "SELECT payload FROM blocks WHERE agent=?", agent)
		if e != nil {
			return Signed{}, e
		}
		for rows.Next() {
			var text string
			rows.Scan(&text)
			var b Block
			json.Unmarshal([]byte(text), &b)
			if b.State == "active" && time.Now().Before(b.Expires) {
				bundle.Blocks = append(bundle.Blocks, b)
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return Signed{}, e
		}
	}
	if s.feed != nil && report.WantFeed {
		version, items, e := s.feed.EndpointFeed(ctx, report.FeedVersion)
		if e != nil {
			return Signed{}, e
		}
		bundle.FeedVersion = version
		if report.FeedVersion != version {
			bundle.IOCs = items
		}
	}
	if !report.WantFeed {
		bundle.FeedVersion = report.FeedVersion
	}
	return Sign(bundle, s.key)
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// Observe creates proposals only. It never authorizes a firewall change.
func (s *Server) Observe(ctx context.Context, detections []telemetry.Detection) error {
	for _, d := range detections {
		if d.SourceIP == "" {
			continue
		}
		p, e := s.policy(ctx, d.AgentID)
		if e != nil {
			return e
		}
		if p.Mode != "learning" {
			continue
		}
		ip, e := netip.ParseAddr(d.SourceIP)
		if e != nil || ip.Zone() != "" || !ip.IsGlobalUnicast() {
			continue
		}
		blocked := false
		for _, value := range p.Protected {
			if prefix, e := netip.ParsePrefix(value); e == nil && prefix.Contains(ip) {
				blocked = true
			}
			if a, e := netip.ParseAddr(value); e == nil && a.Unmap() == ip.Unmap() {
				blocked = true
			}
		}
		if blocked {
			continue
		}
		now := time.Now().UTC()
		b := Block{ID: telemetry.ID("learning/1", d.AgentID, ip.String(), d.Rule, now.Format("2006-01-02"))[:32], Agent: d.AgentID, IP: ip.String(), Created: now, Expires: now.Add(time.Hour), Actor: "correlator", Reason: d.Rule + " · " + d.ID, State: "learning"}
		data, _ := json.Marshal(b)
		result, e := s.db.ExecContext(ctx, "INSERT OR IGNORE INTO blocks VALUES(?,?,?)", b.ID, b.Agent, string(data))
		if e != nil {
			return e
		}
		n, _ := result.RowsAffected()
		if n > 0 {
			if _, e = s.db.ExecContext(ctx, "INSERT INTO audit(at,actor,action,payload) VALUES(?,?,?,?)", now.Format(time.RFC3339), "correlator", "learning.proposal", string(data)); e != nil {
				return e
			}
		}
	}
	return nil
}
