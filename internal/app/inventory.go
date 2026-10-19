// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"fmt"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/event"
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/ports"
	"net"
	"net/netip"
	"time"
)

type InventoryService struct {
	Store  ports.InventoryStore
	Assets interface {
		Assets(context.Context) ([]domain.Asset, error)
	}
}

func (s InventoryService) Import(ctx context.Context, asset string, snapshot inventory.Snapshot) (inventory.Snapshot, error) {
	id, err := domain.NewID()
	if err != nil {
		return snapshot, err
	}
	snapshot.ID = id
	snapshot.AssetID = asset
	if err = snapshot.Validate(); err != nil {
		return snapshot, err
	}
	e, err := event.New("inventory.recorded", asset, map[string]any{"asset_id": asset, "snapshot_id": id, "collected_at": snapshot.CollectedAt, "collector": snapshot.Collector, "coverage": snapshot.Coverage, "components": len(snapshot.Components), "updates": len(snapshot.Updates)})
	if err != nil {
		return snapshot, err
	}
	return snapshot, s.Store.SaveInventory(ctx, snapshot, e)
}
func (s InventoryService) CollectLocal(ctx context.Context, asset string, collector ports.InventoryCollector) (inventory.Snapshot, error) {
	var empty inventory.Snapshot
	assets, err := s.Assets.Assets(ctx)
	if err != nil {
		return empty, err
	}
	var ip string
	for _, a := range assets {
		if a.ID == asset {
			ip = a.IP
			break
		}
	}
	if ip == "" {
		return empty, domain.ErrNotFound
	}
	if err = VerifyLocalAddress(ip); err != nil {
		return empty, err
	}
	snapshot, err := collector.Collect(ctx)
	if err != nil {
		return snapshot, err
	}
	return s.Import(ctx, asset, snapshot)
}
func VerifyLocalAddress(value string) error {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return err
	}
	address = address.Unmap()
	if address.IsLoopback() {
		return nil
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	for _, local := range addresses {
		prefix, err := netip.ParsePrefix(local.String())
		if err == nil && prefix.Addr().Unmap() == address {
			return nil
		}
	}
	return fmt.Errorf("collect-local cannot attach this machine's inventory to a non-local asset")
}
func (s InventoryService) SaveCheck(ctx context.Context, snapshot inventory.Snapshot, source string, results []inventory.Availability) (inventory.Check, error) {
	id, err := domain.NewID()
	if err != nil {
		return inventory.Check{}, err
	}
	check := inventory.Check{ID: id, AssetID: snapshot.AssetID, InventoryID: snapshot.ID, Source: source, CheckedAt: time.Now().UTC(), Results: results}
	e, err := event.New("updates.checked", snapshot.AssetID, check)
	if err != nil {
		return check, err
	}
	return check, s.Store.SaveUpdateCheck(ctx, check, e)
}
