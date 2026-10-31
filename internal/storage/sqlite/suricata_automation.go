// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rkislov/cerber/internal/ingest"
	rules "github.com/rkislov/cerber/internal/suricatarules"
)

func defaultSuricataFeed(major int) rules.Feed {
	now := time.Now().UTC()
	next := time.Date(now.Year(), now.Month(), now.Day()+1, 1, 0, 0, 0, time.UTC)
	return rules.Feed{EngineMajor: major, IntervalHours: 24, NextRunAt: next, State: "idle"}
}
func readSuricataFeed(ctx context.Context, q rowQuerier, major int) (rules.Feed, error) {
	f := defaultSuricataFeed(major)
	var p, lease, until string
	e := q.QueryRowContext(ctx, "SELECT payload,lease,lease_until FROM suricata_feeds WHERE major=?", major).Scan(&p, &lease, &until)
	if errors.Is(e, sql.ErrNoRows) {
		return f, nil
	}
	if e != nil {
		return f, e
	}
	e = json.Unmarshal([]byte(p), &f)
	f.Lease = lease
	if until != "" {
		f.LeaseUntil, _ = parse(until)
	}
	return f, e
}
func saveSuricataFeed(ctx context.Context, tx *sql.Tx, f rules.Feed) error {
	p, _ := json.Marshal(f)
	_, e := tx.ExecContext(ctx, "INSERT INTO suricata_feeds VALUES(?,?,?,?) ON CONFLICT(major) DO UPDATE SET payload=excluded.payload,lease=excluded.lease,lease_until=excluded.lease_until", f.EngineMajor, string(p), f.Lease, stamp(f.LeaseUntil))
	return e
}
func (s *Store) SuricataFeeds(ctx context.Context) ([]rules.Feed, error) {
	out := []rules.Feed{}
	for _, major := range []int{7, 8} {
		f, e := readSuricataFeed(ctx, s.db, major)
		if e != nil {
			return nil, e
		}
		out = append(out, f)
	}
	return out, nil
}
func automationHistory(ctx context.Context, tx *sql.Tx, subject, kind, actor string, v any) error {
	p, _ := json.Marshal(v)
	if _, e := tx.ExecContext(ctx, "INSERT INTO suricata_automation_history(subject,at,kind,payload) VALUES(?,?,?,?)", subject, stamp(time.Now()), kind, string(p)); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, "DELETE FROM suricata_automation_history WHERE subject=? AND seq NOT IN (SELECT seq FROM suricata_automation_history WHERE subject=? ORDER BY seq DESC LIMIT 50)", subject, subject); e != nil {
		return e
	}
	return suricataAudit(ctx, tx, kind, subject, actor, v)
}
func (s *Store) SuricataAutomationHistory(ctx context.Context, subject string) ([]map[string]any, error) {
	rows, e := s.db.QueryContext(ctx, "SELECT at,kind,payload FROM suricata_automation_history WHERE subject=? ORDER BY seq DESC LIMIT 50", subject)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var at, kind, p string
		if e = rows.Scan(&at, &kind, &p); e != nil {
			return nil, e
		}
		out = append(out, map[string]any{"at": at, "kind": kind, "data": json.RawMessage(p)})
	}
	return out, rows.Err()
}
func (s *Store) SetSuricataFeed(ctx context.Context, c rules.FeedChange) (rules.Feed, error) {
	var out rules.Feed
	now := time.Now().UTC()
	if (c.EngineMajor != 7 && c.EngineMajor != 8) || c.ExpectedRevision < 0 || c.ExpectedRevision >= 1<<53-1 {
		return out, rules.ErrInvalid
	}
	if !c.RunNow && (c.IntervalHours < 1 || c.IntervalHours > 168 || (c.Enabled && c.NextRunAt.Before(now.Add(-time.Minute))) || c.NextRunAt.After(now.Add(366*24*time.Hour))) {
		return out, rules.ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	u, e := suricataAdmin(ctx, tx)
	if e != nil {
		return out, e
	}
	f, e := readSuricataFeed(ctx, tx, c.EngineMajor)
	if e != nil {
		return out, e
	}
	if f.Revision != c.ExpectedRevision {
		return out, rules.ErrConflict
	}
	if c.RunNow && f.Lease != "" && f.LeaseUntil.After(now) {
		return out, rules.ErrConflict
	}
	f.Revision++
	f.UpdatedBy = u.Username
	f.Lease = ""
	f.LeaseUntil = time.Time{}
	f.Error = ""
	f.State = "idle"
	if c.RunNow {
		f.Requested = true
		f.State = "queued"
	} else {
		f.Enabled = c.Enabled
		f.IntervalHours = c.IntervalHours
		f.NextRunAt = c.NextRunAt.UTC()
		if !c.Enabled && f.NextRunAt.Before(now) {
			f.NextRunAt = now.Add(time.Duration(c.IntervalHours) * time.Hour)
		}
		f.Requested = false
	}
	if e = saveSuricataFeed(ctx, tx, f); e != nil {
		return out, e
	}
	if e = automationHistory(ctx, tx, fmt.Sprint("feed:", c.EngineMajor), "suricata.schedule_saved", u.Username, f); e != nil {
		return out, e
	}
	return f, tx.Commit()
}
func (s *Store) ClaimSuricataFeed(ctx context.Context, now time.Time) (*rules.Feed, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	for _, major := range []int{7, 8} {
		f, e := readSuricataFeed(ctx, tx, major)
		if e != nil {
			return nil, e
		}
		if (!f.Requested && (!f.Enabled || f.NextRunAt.After(now))) || (f.Lease != "" && f.LeaseUntil.After(now)) {
			continue
		}
		token := make([]byte, 16)
		if _, e = rand.Read(token); e != nil {
			return nil, e
		}
		f.Lease = hex.EncodeToString(token)
		f.LeaseUntil = now.Add(5 * time.Minute)
		f.State = "downloading"
		f.LastStartedAt = now
		f.Requested = true
		f.Error = ""
		if e = saveSuricataFeed(ctx, tx, f); e != nil {
			return nil, e
		}
		return &f, tx.Commit()
	}
	return nil, nil
}
func shortRuleError(e error) string {
	if e == nil {
		return ""
	}
	s := []rune(e.Error())
	if len(s) > 400 {
		s = s[:400]
	}
	return string(s)
}
func (s *Store) CompleteSuricataFeed(ctx context.Context, task rules.Feed, b rules.Bundle, downloadErr error, now time.Time) error {
	if downloadErr == nil {
		if b.Manifest.EngineMajor != task.EngineMajor || b.Manifest.Source != "et-open" {
			downloadErr = rules.ErrInvalid
		} else {
			_, downloadErr = rules.Unpack(b.Manifest, b.Data)
		}
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	f, e := readSuricataFeed(ctx, tx, task.EngineMajor)
	if e != nil {
		return e
	}
	if f.Revision != task.Revision || f.Lease == "" || f.Lease != task.Lease || now.After(f.LeaseUntil) {
		return rules.ErrConflict
	}
	if downloadErr == nil {
		var m rules.Manifest
		m, downloadErr = putSuricataBundle(ctx, tx, b, "system:suricata", true)
		if downloadErr == nil {
			f.State = "updated"
			if f.LatestID == m.ID {
				f.State = "unchanged"
			}
			f.LatestID = m.ID
		}
	}
	f.Error = shortRuleError(downloadErr)
	if downloadErr != nil {
		f.State = "error"
	}
	f.Requested = false
	f.Lease = ""
	f.LeaseUntil = time.Time{}
	f.LastFinishedAt = now
	if !f.NextRunAt.After(now) {
		d := time.Duration(f.IntervalHours) * time.Hour
		f.NextRunAt = f.NextRunAt.Add((now.Sub(f.NextRunAt)/d + 1) * d)
	}
	if e = saveSuricataFeed(ctx, tx, f); e != nil {
		return e
	}
	if e = automationHistory(ctx, tx, fmt.Sprint("feed:", f.EngineMajor), "suricata.feed_completed", "system:suricata", f); e != nil {
		return e
	}
	return tx.Commit()
}
func readSuricataGroup(ctx context.Context, q rowQuerier, id string) (rules.GroupPolicy, error) {
	p := rules.GroupPolicy{GroupID: id, EngineMajor: 7, Mode: "pinned", State: "idle"}
	var data string
	e := q.QueryRowContext(ctx, "SELECT payload FROM suricata_group_rules WHERE group_id=?", id).Scan(&data)
	if errors.Is(e, sql.ErrNoRows) {
		return p, nil
	}
	if e == nil {
		e = json.Unmarshal([]byte(data), &p)
	}
	return p, e
}
func saveSuricataGroup(ctx context.Context, tx *sql.Tx, p rules.GroupPolicy) error {
	b, _ := json.Marshal(p)
	_, e := tx.ExecContext(ctx, "INSERT INTO suricata_group_rules VALUES(?,?) ON CONFLICT(group_id) DO UPDATE SET payload=excluded.payload", p.GroupID, string(b))
	return e
}
func (s *Store) SetSuricataGroup(ctx context.Context, c rules.GroupChange) (rules.GroupPolicy, error) {
	var out rules.GroupPolicy
	if !ingest.Identifier(c.GroupID) || c.ExpectedRevision < 0 || c.ExpectedRevision >= 1<<53-1 {
		return out, rules.ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	u, e := suricataAdmin(ctx, tx)
	if e != nil {
		return out, e
	}
	g, e := groupInfo(ctx, tx, c.GroupID)
	if e != nil {
		return out, rules.ErrNotFound
	}
	old, e := readSuricataGroup(ctx, tx, c.GroupID)
	if e != nil {
		return out, e
	}
	if old.Revision != c.ExpectedRevision {
		return out, rules.ErrConflict
	}
	r, e := readSuricataRollout(ctx, tx, c.GroupID)
	if e != nil {
		return out, e
	}
	if r != nil && rules.RolloutHolds(r.State) {
		if !(c.Rollback && (r.State == "canary" || r.State == "fleet")) && !(c.RetryRollback && r.State == "rollback_failed") {
			return out, rules.ErrConflict
		}
		old.Revision++
		r.PolicyRevision = old.Revision
		if e = beginSuricataRollback(ctx, tx, &old, r, "Остановка и откат по запросу администратора", u.Username, time.Now().UTC()); e != nil {
			return out, e
		}
		if e = saveSuricataRollout(ctx, tx, r); e != nil {
			return out, e
		}
		if e = saveSuricataGroup(ctx, tx, old); e != nil {
			return out, e
		}
		return old, tx.Commit()
	}
	if c.RetryRollback {
		return out, rules.ErrConflict
	}
	if g.Archived {
		return out, rules.ErrConflict
	}
	if old.Revision == 0 {
		var count int
		if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM suricata_group_rules").Scan(&count); e != nil {
			return out, e
		}
		if count >= 32 {
			return out, rules.ErrLimit
		}
	}
	if c.Rollback {
		if old.PreviousID == "" {
			return out, rules.ErrConflict
		}
		c.GroupPolicy = old
		c.Enabled = true
		c.Mode = "pinned"
		c.BundleID = old.PreviousID
		b, e := suricataBundle(ctx, tx, c.BundleID)
		if e != nil {
			return out, e
		}
		c.EngineMajor = b.Manifest.EngineMajor
		c.CustomID = ""
	}
	if (c.EngineMajor != 7 && c.EngineMajor != 8) || (c.Mode != "pinned" && c.Mode != "et_open") {
		return out, rules.ErrInvalid
	}
	p := rules.GroupPolicy{Rollout: c.Rollout, GroupID: c.GroupID, Revision: old.Revision + 1, Enabled: c.Enabled, EngineMajor: c.EngineMajor, Mode: c.Mode, BundleID: c.BundleID, CustomID: c.CustomID, ActiveID: old.ActiveID, PreviousID: old.PreviousID, State: "waiting_feed", UpdatedBy: u.Username, UpdatedAt: time.Now().UTC()}
	if e = validateRolloutConfig(ctx, tx, p); e != nil {
		return out, e
	}
	if p.Mode == "pinned" {
		b, e := suricataBundle(ctx, tx, p.BundleID)
		if e != nil {
			return out, e
		}
		if b.Manifest.EngineMajor != p.EngineMajor || p.CustomID != "" {
			return out, rules.ErrInvalid
		}
		if p.Rollout == nil && p.ActiveID != p.BundleID {
			p.PreviousID = p.ActiveID
			p.ActiveID = p.BundleID
		}
		p.State = "ready"
		if p.Rollout != nil && p.Enabled {
			if e = prepareSuricataRollout(ctx, tx, &p, p.BundleID, time.Now().UTC()); e != nil {
				return out, e
			}
		}
	} else {
		if p.BundleID != "" {
			return out, rules.ErrInvalid
		}
		if p.CustomID != "" {
			b, e := suricataBundle(ctx, tx, p.CustomID)
			if e != nil {
				return out, e
			}
			if b.Manifest.Source != "custom" || b.Manifest.EngineMajor != p.EngineMajor {
				return out, rules.ErrInvalid
			}
		}
		// A changed automatic recipe cannot fan out the old recipe to new members.
		p.State = "waiting_feed"
	}
	if e = saveSuricataGroup(ctx, tx, p); e != nil {
		return out, e
	}
	kind := "suricata.group_saved"
	if c.Rollback {
		kind = "suricata.group_rollback"
	}
	if e = automationHistory(ctx, tx, p.GroupID, kind, u.Username, p); e != nil {
		return out, e
	}
	return p, tx.Commit()
}
func (s *Store) CompleteSuricataGroup(ctx context.Context, task rules.GroupPolicy, etID string, b rules.Bundle, buildErr error) error {
	if buildErr == nil {
		if b.Manifest.EngineMajor != task.EngineMajor {
			buildErr = rules.ErrInvalid
		} else {
			_, buildErr = rules.Unpack(b.Manifest, b.Data)
		}
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	p, e := readSuricataGroup(ctx, tx, task.GroupID)
	if e != nil {
		return e
	}
	feed, e := readSuricataFeed(ctx, tx, p.EngineMajor)
	if e != nil {
		return e
	}
	g, e := groupInfo(ctx, tx, p.GroupID)
	if e != nil {
		return e
	}
	if p.Revision != task.Revision || !p.Enabled || g.Archived || p.Mode != "et_open" || feed.LatestID != etID || rules.RolloutHolds(p.State) || p.State == "blocked" || p.State == "rolled_back" {
		return rules.ErrConflict
	}
	p.Revision++
	if buildErr == nil {
		p.Error = ""
		var m rules.Manifest
		m, buildErr = putSuricataBundle(ctx, tx, b, "system:suricata", true)
		if buildErr == nil {
			if p.Rollout == nil && p.ActiveID != m.ID {
				p.PreviousID = p.ActiveID
				p.ActiveID = m.ID
			}
			p.State = "ready"
			if p.Rollout != nil {
				if e = prepareSuricataRollout(ctx, tx, &p, m.ID, time.Now().UTC()); e != nil {
					return e
				}
			}
		}
	}
	p.BuiltETID = etID
	if buildErr != nil {
		p.Error = shortRuleError(buildErr)
		p.State = "error"
	}
	p.UpdatedAt = time.Now().UTC()
	if e = saveSuricataGroup(ctx, tx, p); e != nil {
		return e
	}
	if e = automationHistory(ctx, tx, p.GroupID, "suricata.group_built", "system:suricata", p); e != nil {
		return e
	}
	return tx.Commit()
}
