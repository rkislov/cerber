// SPDX-License-Identifier: Apache-2.0
package endpoint

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/attack"
	"github.com/rkislov/cerber/internal/netscan"
	"github.com/rkislov/cerber/internal/telemetry"
	"github.com/rkislov/cerber/internal/vuln"
	"reflect"
	"sort"
	"time"
)

type NetworkView struct {
	Catalog vuln.Status     `json:"catalog"`
	Plans   []netscan.Plan  `json:"plans"`
	Runs    []netscan.Run   `json:"runs"`
	Assets  []netscan.Asset `json:"assets"`
}
type NetworkCommand struct {
	Action string       `json:"action"`
	Plan   netscan.Plan `json:"plan"`
	ID     string       `json:"id"`
}

func (s *Server) networkLoad(ctx context.Context) (NetworkView, error) {
	v := NetworkView{Plans: []netscan.Plan{}, Runs: []netscan.Run{}, Assets: []netscan.Asset{}}
	_, e := s.db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS network_state(id INTEGER PRIMARY KEY CHECK(id=1),payload TEXT NOT NULL)")
	if e != nil {
		return v, e
	}
	var data string
	e = s.db.QueryRowContext(ctx, "SELECT payload FROM network_state WHERE id=1").Scan(&data)
	if e == sql.ErrNoRows {
		return v, nil
	}
	if e != nil {
		return v, e
	}
	e = json.Unmarshal([]byte(data), &v)
	return v, e
}
func (s *Server) networkSave(ctx context.Context, v NetworkView) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	_, e = s.db.ExecContext(ctx, "INSERT INTO network_state VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", string(b))
	return e
}
func (s *Server) NetworkView(ctx context.Context) (NetworkView, error) {
	s.mu.Lock()
	v, e := s.networkLoad(ctx)
	s.mu.Unlock()
	if e != nil {
		return v, e
	}
	if s.Catalog != nil {
		v.Catalog = s.Catalog.Status(ctx)
		for i := range v.Assets {
			h := &v.Assets[i].Host
			h.Vulnerabilities = s.networkVulns(ctx, *h)
		}
	}
	return v, nil
}
func (s *Server) NetworkCommand(ctx context.Context, c NetworkCommand, actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if actor == "" {
		return ErrInvalid
	}
	v, e := s.networkLoad(ctx)
	if e != nil {
		return e
	}
	now := time.Now().UTC()
	switch c.Action {
	case "sync":
		if s.Catalog != nil {
			s.Catalog.Request()
		}
	case "create":
		if len(v.Plans) >= 100 || c.Plan.Validate() != nil || !telemetry.AgentIdentifier(c.Plan.Agent) {
			return ErrInvalid
		}
		if _, _, e = netscan.Window(c.Plan.CIDR, ""); e != nil {
			return e
		}
		p := c.Plan
		p.ID = telemetry.ID(actor, p.Name, now.String())[:32]
		p.Cursor = ""
		if p.Next.IsZero() || p.Next.Before(now) {
			p.Next = now
		}
		if p.Next.After(now.Add(365 * 24 * time.Hour)) {
			return ErrInvalid
		}
		v.Plans = append(v.Plans, p)
		c.Plan = p
	case "pause", "resume", "run":
		found := false
		for i := range v.Plans {
			p := &v.Plans[i]
			if p.ID == c.ID {
				found = true
				if c.Action == "pause" {
					p.Enabled = false
				} else {
					p.Enabled = true
					p.Next = now
				}
			}
		}
		if !found {
			return ErrInvalid
		}
	case "cancel":
		found := false
		for i := range v.Runs {
			r := &v.Runs[i]
			if r.Task.ID == c.ID && r.Result.State == "running" {
				r.Result.State = "cancelled"
				r.Result.Finished = now
				found = true
			}
		}
		if !found {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	b, _ := json.Marshal(v)
	if _, e = tx.ExecContext(ctx, "INSERT INTO network_state VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", string(b)); e != nil {
		return e
	}
	b, _ = json.Marshal(c)
	if _, e = tx.ExecContext(ctx, "INSERT INTO audit(at,actor,action,payload) VALUES(?,?,?,?)", now.Format(time.RFC3339), actor, "network."+c.Action, string(b)); e != nil {
		return e
	}
	return tx.Commit()
}

// Called under s.mu. A durable lease prevents duplicate concurrent assignment.
func (s *Server) networkExchange(ctx context.Context, agent string, result *netscan.Result) (*netscan.Task, error) {
	v, e := s.networkLoad(ctx)
	if e != nil {
		return nil, e
	}
	now := time.Now().UTC()
	for i := range v.Runs {
		r := &v.Runs[i]
		if r.Task.Agent != agent || r.Result.State != "running" {
			continue
		}
		if result != nil && result.ID == r.Task.ID {
			if e = validateNetworkResult(r.Task, *result); e != nil {
				return nil, e
			}
			r.Result = *result
			if result.State == "completed" {
				newCount := 0
				for _, h := range result.Hosts {
					found := false
					for _, a := range v.Assets {
						if a.Plan == r.Task.Plan && a.Host.IP == h.IP {
							found = true
							break
						}
					}
					if !found {
						newCount++
					}
				}
				if len(v.Assets)+newCount > 10000 {
					r.Result.State = "failed"
					r.Result.Error = "Asset limit (10000) reached; reduce scope or archive old assets"
				} else {
					mergeAssets(&v, *r, now)
					_, next, err := netscan.Window(r.Task.CIDR, r.Task.Targets[0])
					if err != nil {
						return nil, err
					}
					for j := range v.Plans {
						if v.Plans[j].ID == r.Task.Plan {
							v.Plans[j].Cursor = next
						}
					}
				}
			}
		} else if !now.Before(r.Task.Expires) {
			r.Result.State = "expired"
			r.Result.Error = "Agent did not return a result before lease expiry"
			r.Result.Finished = now
		}
	}
	for _, r := range v.Runs {
		if r.Task.Agent == agent && r.Result.State == "running" {
			task := r.Task
			return &task, s.networkSave(ctx, v)
		}
	}
	var task *netscan.Task
	for i := range v.Plans {
		p := &v.Plans[i]
		if p.Agent != agent || !p.Enabled || now.Before(p.Next) {
			continue
		}
		targets, _, e := netscan.Window(p.CIDR, p.Cursor)
		if e != nil {
			return nil, e
		}
		t := netscan.Task{ID: telemetry.ID(p.ID, now.String())[:32], Plan: p.ID, Agent: agent, CIDR: p.CIDR, Profile: p.Profile, Targets: targets, Expires: now.Add(15 * time.Minute)}
		p.Next = now.Add(time.Duration(p.Interval) * time.Minute)
		v.Runs = append(v.Runs, netscan.Run{Task: t, Result: netscan.Result{ID: t.ID, State: "running", Hosts: []netscan.Host{}}, Created: now})
		task = &t
		break
	}
	// Keep active runs and the most recent 100 terminal records.
	terminal := 0
	keep := []netscan.Run{}
	for i := len(v.Runs) - 1; i >= 0; i-- {
		r := v.Runs[i]
		if r.Result.State == "running" || terminal < 100 {
			keep = append([]netscan.Run{r}, keep...)
			if r.Result.State != "running" {
				terminal++
			}
		}
	}
	v.Runs = keep
	return task, s.networkSave(ctx, v)
}
func validateNetworkResult(t netscan.Task, r netscan.Result) error {
	if r.State != "completed" && r.State != "failed" && r.State != "interrupted" {
		return ErrInvalid
	}
	if len(r.Hosts) > 256 || len(r.Error) > 2000 || r.Started.IsZero() || r.Finished.IsZero() {
		return ErrInvalid
	}
	allowed := map[string]bool{}
	for _, ip := range t.Targets {
		allowed[ip] = true
	}
	seen := map[string]bool{}
	for _, h := range r.Hosts {
		if !allowed[h.IP] || seen[h.IP] || len(h.Name) > 253 || len(h.Services) > 28 || len(h.Findings) > 140 {
			return ErrInvalid
		}
		seen[h.IP] = true
		for _, p := range h.Services {
			if p.Port < 1 || p.Port > 65535 || len(p.Product) > 512 || len(p.Version) > 512 || len(p.Name) > 128 || len(p.CPE) > 10 {
				return ErrInvalid
			}
			for _, c := range p.CPE {
				if len(c) > 1024 {
					return ErrInvalid
				}
			}
		}
		for _, f := range h.Findings {
			if len(f.Evidence) > 4000 || !knownNetworkCheck(f.Script) || (f.Status != "scanner_confirmed" && f.Status != "not_confirmed") {
				return ErrInvalid
			}
		}
	}
	return nil
}
func mergeAssets(v *NetworkView, r netscan.Run, now time.Time) {
	seen := map[string]bool{}
	for _, h := range r.Result.Hosts {
		seen[h.IP] = true
		found := false
		for i := range v.Assets {
			a := &v.Assets[i]
			if a.Plan == r.Task.Plan && a.Host.IP == h.IP {
				found = true
				a.New = false
				if !reflect.DeepEqual(a.Host, h) {
					a.Changed = now
				}
				a.Host = h
				a.Last = now
				a.State = "observed"
				break
			}
		}
		if !found && len(v.Assets) < 10000 {
			v.Assets = append(v.Assets, netscan.Asset{Plan: r.Task.Plan, Agent: r.Task.Agent, Host: h, First: now, Last: now, Changed: now, State: "observed", New: true})
		}
	}
	targets := map[string]bool{}
	for _, ip := range r.Task.Targets {
		targets[ip] = true
	}
	for i := range v.Assets {
		a := &v.Assets[i]
		if a.Plan == r.Task.Plan && targets[a.Host.IP] && !seen[a.Host.IP] {
			a.State = "not_observed"
			a.New = false
		}
	}
}

func knownNetworkCheck(id string) bool { _, ok := netscan.Checks[id]; return ok }
func (s *Server) networkVulns(ctx context.Context, h netscan.Host) []vuln.Match {
	out := []vuln.Match{}
	seen := map[string]int{}
	for _, svc := range h.Services {
		for _, cpe := range svc.Identities() {
			for _, m := range s.Catalog.Lookup(ctx, cpe) {
				if _, ok := seen[m.ID]; ok {
					continue
				}
				m.Evidence = "Порт " + fmt.Sprint(svc.Port) + " · " + m.Evidence
				seen[m.ID] = len(out)
				out = append(out, m)
			}
		}
	}
	for _, f := range h.Findings {
		if f.Status != "scanner_confirmed" {
			continue
		}
		for _, id := range netscan.Checks[f.Script] {
			if i, ok := seen[id]; ok {
				out[i].Status = "scanner_confirmed"
				out[i].Evidence = f.Script + ": " + f.Evidence
				continue
			}
			for i := range out {
				for _, cve := range out[i].CVEs {
					if cve == id {
						seen[id] = i
					}
				}
			}
			if i, ok := seen[id]; ok {
				out[i].Status = "scanner_confirmed"
				out[i].Evidence = f.Script + ": " + f.Evidence
				continue
			}
			links := s.Catalog.BDU(ctx, id)
			r := vuln.Record{ID: id, Title: id, Source: "Nmap NSE", URL: "https://nvd.nist.gov/vuln/detail/" + id, Severity: "unknown"}
			for _, b := range links {
				if b.Score > r.Score {
					r.Score = b.Score
					r.Vector = b.Vector
					r.Severity = b.Severity
				}
			}
			seen[id] = len(out)
			out = append(out, vuln.Match{Record: r, Status: "scanner_confirmed", Evidence: f.Script + ": " + f.Evidence, BDU: links})
		}
	}
	for i := range out {
		ids := append([]string{out[i].ID}, out[i].CVEs...)
		out[i].Attack = attack.Vulnerability(ids, out[i].Vector, out[i].Status)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}
func (s *Server) RunNetworkCatalog(ctx context.Context) {
	for {
		s.mu.Lock()
		v, e := s.networkLoad(ctx)
		s.mu.Unlock()
		if e == nil {
			cpes := []string{}
			for _, a := range v.Assets {
				for _, svc := range a.Host.Services {
					cpes = append(cpes, svc.Identities()...)
				}
			}
			s.Catalog.Sync(ctx, cpes)
		}
		timer := time.NewTimer(time.Minute)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
