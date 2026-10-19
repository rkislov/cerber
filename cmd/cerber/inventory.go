// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/app"
	"github.com/rkislov/cerber/internal/collector/windows"
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"github.com/rkislov/cerber/internal/updates/microsoft"
	"io"
	"os"
)

func inventoryCommand(ctx context.Context, store *sqlite.Store, args []string, out, errOut io.Writer) error {
	f := flags(args[0]+" "+args[1], errOut)
	service := app.InventoryService{Store: store, Assets: store}
	var result any
	command := args[0] + " " + args[1]
	switch command {
	case "inventory import":
		asset := f.String("asset", "", "asset ID")
		file := f.String("file", "", "inventory JSON file")
		if err := parse(f, args[2:]); err != nil {
			return err
		}
		input, err := os.Open(*file)
		if err != nil {
			return err
		}
		defer input.Close()
		data, err := io.ReadAll(io.LimitReader(input, inventory.MaxSnapshotBytes+1))
		if err != nil {
			return err
		}
		if int64(len(data)) > inventory.MaxSnapshotBytes {
			return fmt.Errorf("inventory exceeds 32 MiB")
		}
		var snapshot inventory.Snapshot
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&snapshot); err != nil {
			return err
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return fmt.Errorf("trailing inventory JSON data")
		}
		result, err = service.Import(ctx, *asset, snapshot)
		if err != nil {
			return err
		}
	case "inventory collect-local":
		asset := f.String("asset", "", "local asset ID")
		online := f.Bool("check-windows-updates", false, "query configured Windows update service online; no downloads or installs")
		if err := parse(f, args[2:]); err != nil {
			return err
		}
		var err error
		result, err = service.CollectLocal(ctx, *asset, windows.Collector{CheckAvailable: *online})
		if err != nil {
			return err
		}
	case "inventory list":
		asset := f.String("asset", "", "asset ID")
		limit := f.Int("limit", 10, "maximum snapshots (1–100)")
		if err := parse(f, args[2:]); err != nil {
			return err
		}
		var err error
		result, err = store.Inventories(ctx, *asset, *limit)
		if err != nil {
			return err
		}
	case "inventory show":
		id := f.String("id", "", "snapshot ID")
		if err := parse(f, args[2:]); err != nil {
			return err
		}
		var err error
		result, err = store.Inventory(ctx, *id)
		if err != nil {
			return err
		}
	case "inventory diff":
		before := f.String("before", "", "earlier snapshot ID")
		after := f.String("after", "", "later snapshot ID")
		if err := parse(f, args[2:]); err != nil {
			return err
		}
		a, err := store.Inventory(ctx, *before)
		if err != nil {
			return err
		}
		b, err := store.Inventory(ctx, *after)
		if err != nil {
			return err
		}
		result, err = inventory.Diff(a, b)
		if err != nil {
			return err
		}
	case "updates edge":
		id := f.String("inventory", "", "inventory snapshot ID")
		componentID := f.String("component", "", "explicit Edge component ID")
		channel := f.String("channel", "Stable", "Edge channel: Stable, Beta, Dev")
		arch := f.String("architecture", "", "explicit Edge architecture: x64, x86, arm64")
		if err := parse(f, args[2:]); err != nil {
			return err
		}
		snapshot, err := store.Inventory(ctx, *id)
		if err != nil {
			return err
		}
		if snapshot.OS.Family != "windows" {
			return fmt.Errorf("Edge Windows source requires a Windows inventory")
		}
		var component *inventory.Component
		for _, c := range snapshot.Components {
			if c.ID == *componentID && c.Kind == "application" {
				copy := c
				component = &copy
				break
			}
		}
		if component == nil {
			return fmt.Errorf("application component not found in inventory")
		}
		available, sourceErr := (microsoft.EdgeClient{}).Check(ctx, *component, *channel, *arch)
		if sourceErr != nil {
			available.Status = "source_error"
			available.Detail = sourceErr.Error()
		}
		check, err := service.SaveCheck(ctx, snapshot, "microsoft-edge", []inventory.Availability{available})
		if err != nil {
			return err
		}
		if err = json.NewEncoder(out).Encode(check); err != nil {
			return err
		}
		return sourceErr
	case "updates list":
		asset := f.String("asset", "", "asset ID")
		limit := f.Int("limit", 10, "maximum checks (1–100)")
		if err := parse(f, args[2:]); err != nil {
			return err
		}
		var err error
		result, err = store.UpdateChecks(ctx, *asset, *limit)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown inventory/update command")
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
