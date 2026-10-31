// SPDX-License-Identifier: Apache-2.0
package suricatarules

import (
	"context"
	"time"
)

// Feed configuration and execution state are durable. Revision fences an in-flight
// download when an administrator changes or disables its schedule.
type Feed struct {
	EngineMajor    int       `json:"engine_major"`
	Revision       int64     `json:"revision"`
	Enabled        bool      `json:"enabled"`
	IntervalHours  int       `json:"interval_hours"`
	NextRunAt      time.Time `json:"next_run_at"`
	LatestID       string    `json:"latest_id,omitempty"`
	State          string    `json:"state"`
	Error          string    `json:"error,omitempty"`
	LastStartedAt  time.Time `json:"last_started_at"`
	LastFinishedAt time.Time `json:"last_finished_at"`
	UpdatedBy      string    `json:"updated_by"`
	Requested      bool      `json:"requested"`
	Lease          string    `json:"-"`
	LeaseUntil     time.Time `json:"-"`
}
type FeedChange struct {
	EngineMajor      int       `json:"engine_major"`
	ExpectedRevision int64     `json:"expected_revision"`
	Enabled          bool      `json:"enabled"`
	IntervalHours    int       `json:"interval_hours"`
	NextRunAt        time.Time `json:"next_run_at"`
	RunNow           bool      `json:"run_now"`
}
type GroupPolicy struct {
	GroupID     string    `json:"group_id"`
	Revision    int64     `json:"revision"`
	Enabled     bool      `json:"enabled"`
	EngineMajor int       `json:"engine_major"`
	Mode        string    `json:"mode"`
	BundleID    string    `json:"bundle_id,omitempty"`
	CustomID    string    `json:"custom_id,omitempty"`
	ActiveID    string    `json:"active_id,omitempty"`
	PreviousID  string    `json:"previous_id,omitempty"`
	BuiltETID   string    `json:"built_et_id,omitempty"`
	State       string    `json:"state"`
	Error       string    `json:"error,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
	UpdatedBy   string    `json:"updated_by"`
}
type GroupChange struct {
	GroupPolicy
	ExpectedRevision int64 `json:"expected_revision"`
	Rollback         bool  `json:"rollback"`
}
type GroupMember struct {
	AgentID       string    `json:"agent_id"`
	Name          string    `json:"name"`
	State         string    `json:"state"`
	Error         string    `json:"error,omitempty"`
	AppliedID     string    `json:"applied_id,omitempty"`
	DesiredID     string    `json:"desired_id,omitempty"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
}
type GroupView struct {
	Policy   GroupPolicy   `json:"policy"`
	Name     string        `json:"name"`
	Archived bool          `json:"archived"`
	Members  []GroupMember `json:"members"`
}
type AutomationStore interface {
	ClaimSuricataFeed(context.Context, time.Time) (*Feed, error)
	CompleteSuricataFeed(context.Context, Feed, Bundle, error, time.Time) error
	SuricataGroups(context.Context) ([]GroupView, error)
	SuricataFeeds(context.Context) ([]Feed, error)
	SuricataBundle(context.Context, string) (Bundle, error)
	CompleteSuricataGroup(context.Context, GroupPolicy, string, Bundle, error) error
}

// Tick never performs HTTP or decompression while holding a database transaction.
// Only the store's fenced completion may publish a candidate or move a group.
func Tick(ctx context.Context, s AutomationStore, download func(context.Context, int) (Bundle, error)) error {
	task, e := s.ClaimSuricataFeed(ctx, time.Now().UTC())
	if e != nil {
		return e
	}
	if task != nil {
		b, err := download(ctx, task.EngineMajor)
		if e = s.CompleteSuricataFeed(ctx, *task, b, err, time.Now().UTC()); e != nil && e != ErrConflict {
			return e
		}
	}
	feeds, e := s.SuricataFeeds(ctx)
	if e != nil {
		return e
	}
	groups, e := s.SuricataGroups(ctx)
	if e != nil {
		return e
	}
	latest := map[int]string{}
	for _, f := range feeds {
		latest[f.EngineMajor] = f.LatestID
	}
	for _, g := range groups {
		p := g.Policy
		id := latest[p.EngineMajor]
		if !p.Enabled || g.Archived || p.Mode != "et_open" || id == "" || p.BuiltETID == id {
			continue
		}
		b, err := s.SuricataBundle(ctx, id)
		if err == nil && p.CustomID != "" {
			var custom Bundle
			custom, err = s.SuricataBundle(ctx, p.CustomID)
			if err == nil {
				var plain, extra []byte
				plain, err = Unpack(b.Manifest, b.Data)
				if err == nil {
					extra, err = Unpack(custom.Manifest, custom.Data)
				}
				if err == nil {
					b, err = Pack("ET Open + собственные правила", "combined", p.EngineMajor, append(plain, extra...))
				}
			}
		}
		if e = s.CompleteSuricataGroup(ctx, p, id, b, err); e != nil && e != ErrConflict {
			return e
		}
	}
	return nil
}
func RunAutomation(ctx context.Context, s AutomationStore, onError func(error)) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		work, cancel := context.WithTimeout(ctx, 4*time.Minute)
		e := Tick(work, s, DownloadET)
		cancel()
		if e != nil && ctx.Err() == nil && onError != nil {
			onError(e)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
