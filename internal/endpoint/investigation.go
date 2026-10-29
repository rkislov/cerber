// SPDX-License-Identifier: Apache-2.0
package endpoint

import (
	"context"
	"fmt"
	"github.com/rkislov/cerber/internal/telemetry"
	"github.com/rkislov/cerber/internal/vuln"
	"sort"
	"time"
)

type InvestigationAsset struct {
	IP         string             `json:"ip"`
	Plan       string             `json:"plan"`
	AgentID    string             `json:"agent_id"`
	AssetID    string             `json:"asset_id"`
	ObservedAt time.Time          `json:"observed_at"`
	Stale      bool               `json:"stale"`
	Inventory  vuln.InventoryLink `json:"inventory"`
	Findings   []vuln.Match       `json:"findings"`
	Truncated  bool               `json:"truncated"`
}

// InvestigationAssets uses authenticated managed-asset bindings, never an attacker
// source IP or the scanner agent as the asset owner. No scanning/download occurs.
func (s *Server) InvestigationAssets(ctx context.Context, seeds []telemetry.Detection) ([]InvestigationAsset, bool, error) {
	out := []InvestigationAsset{}
	if s.Catalog == nil || s.Inventory == nil {
		return out, false, nil
	}
	identity, ok := s.Inventory.(interface {
		VulnerabilityOwner(context.Context, string) (string, string, error)
	})
	if !ok {
		return out, false, fmt.Errorf("managed asset identity lookup unavailable")
	}
	owners := map[string]bool{}
	for _, d := range seeds {
		if d.AgentID != "" && d.AssetID != "" {
			owners[d.AgentID+":"+d.AssetID] = true
		}
	}
	s.mu.Lock()
	view, e := s.networkLoad(ctx)
	s.mu.Unlock()
	if e != nil {
		return out, false, e
	}
	sort.Slice(view.Assets, func(i, j int) bool {
		a, b := view.Assets[i], view.Assets[j]
		if a.Host.IP != b.Host.IP {
			return a.Host.IP < b.Host.IP
		}
		if !a.Last.Equal(b.Last) {
			return a.Last.After(b.Last)
		}
		return a.Plan < b.Plan
	})
	seen := map[string]bool{}
	truncated := false
	checked := 0
	for _, a := range view.Assets {
		if ctx.Err() != nil {
			return out, truncated, ctx.Err()
		}
		checked++
		if checked > 256 {
			truncated = true
			break
		}
		agent, asset, e := identity.VulnerabilityOwner(ctx, a.Host.IP)
		if e != nil {
			return out, truncated, e
		}
		if !owners[agent+":"+asset] {
			continue
		}
		binding, e := s.Inventory.VulnerabilityInventory(ctx, a.Host.IP)
		if e != nil {
			return out, truncated, e
		}
		if binding.Link.State != "linked" || !owners[binding.Link.AgentID+":"+binding.Snapshot.AssetID] {
			continue
		}
		if seen[a.Host.IP] {
			continue
		}
		seen[a.Host.IP] = true
		if len(out) >= 10 {
			truncated = true
			break
		}
		row := InvestigationAsset{IP: a.Host.IP, Plan: a.Plan, AgentID: binding.Link.AgentID, AssetID: binding.Snapshot.AssetID, ObservedAt: a.Last, Stale: a.Last.IsZero() || time.Since(a.Last) > 24*time.Hour || a.Last.After(time.Now().Add(5*time.Minute)), Inventory: binding.Link, Findings: []vuln.Match{}}
		findings := s.networkVulns(ctx, a.Host)
		if len(findings) > 20 {
			findings = findings[:20]
			row.Truncated = true
		}
		for _, m := range findings {
			assessment := s.Catalog.AssessPackage(ctx, m, binding, time.Now().UTC())
			m.Verification = &assessment
			row.Findings = append(row.Findings, m)
		}
		out = append(out, row)
	}
	return out, truncated, nil
}
