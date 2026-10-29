// SPDX-License-Identifier: Apache-2.0
package endpoint

import (
	"context"
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/netscan"
	"github.com/rkislov/cerber/internal/telemetry"
	"github.com/rkislov/cerber/internal/vuln"
	"testing"
	"time"
)

type investigationInventory struct{ reads int }

func (f *investigationInventory) VulnerabilityOwner(context.Context, string) (string, string, error) {
	return "owner", "owned-asset", nil
}
func (f *investigationInventory) VulnerabilityInventory(context.Context, string) (vuln.InventoryBinding, error) {
	f.reads++
	return vuln.InventoryBinding{Link: vuln.InventoryLink{State: "linked", AgentID: "owner"}, Snapshot: inventory.Snapshot{AssetID: "owned-asset"}}, nil
}
func TestInvestigationEnrichmentUsesOwnerNotScannerOrRemoteIP(t *testing.T) {
	s, _ := fixture(t)
	ctx := context.Background()
	view, e := s.networkLoad(ctx)
	if e != nil {
		t.Fatal(e)
	}
	view.Assets = []netscan.Asset{{Plan: "fixture", Agent: "scanner", Host: netscan.Host{IP: "192.0.2.20"}, Last: time.Now()}}
	if e = s.networkSave(ctx, view); e != nil {
		t.Fatal(e)
	}
	source := &investigationInventory{}
	s.Inventory = source
	rows, _, e := s.InvestigationAssets(ctx, []telemetry.Detection{{AgentID: "scanner", AssetID: "scanner-asset", SourceIP: "192.0.2.20"}})
	if e != nil || len(rows) != 0 || source.reads != 0 {
		t.Fatal("scanner/attacker treated as owner", rows, source.reads, e)
	}
	rows, _, e = s.InvestigationAssets(ctx, []telemetry.Detection{{AgentID: "owner", AssetID: "wrong-asset"}})
	if e != nil || len(rows) != 0 {
		t.Fatal(rows, e)
	}
	rows, _, e = s.InvestigationAssets(ctx, []telemetry.Detection{{AgentID: "owner", AssetID: "owned-asset"}})
	if e != nil || len(rows) != 1 || rows[0].AgentID != "owner" || source.reads != 1 {
		t.Fatal(rows, source.reads, e)
	}
}
