package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/inventory"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInventoryCLIWorkflow(t *testing.T) {
	root := t.TempDir()
	db := filepath.Join(root, "db")
	file := filepath.Join(root, "inventory.json")
	call := func(args ...string) []byte {
		t.Helper()
		var out, errOut bytes.Buffer
		if err := run(context.Background(), append([]string{"-db", db}, args...), &out, &errOut); err != nil {
			t.Fatal(args, err, errOut.String())
		}
		return out.Bytes()
	}
	var asset map[string]any
	if err := json.Unmarshal(call("asset", "add", "-ip", "127.0.0.1"), &asset); err != nil {
		t.Fatal(err)
	}
	value := inventory.Snapshot{SchemaVersion: 1, Collector: "import-test", CollectedAt: time.Now().Add(-time.Minute).UTC(), OS: inventory.OS{Family: "windows"}, Coverage: []inventory.Coverage{{Section: "applications", Status: "complete"}}, Components: []inventory.Component{{ID: "app", Kind: "application", Name: "Example", Version: "1.0", Source: "test"}}}
	save := func() inventory.Snapshot {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
		var result inventory.Snapshot
		if err = json.Unmarshal(call("inventory", "import", "-asset", asset["id"].(string), "-file", file), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	first := save()
	value.Components[0].Version = "2.0"
	value.CollectedAt = value.CollectedAt.Add(time.Second)
	second := save()
	var changes []inventory.Change
	if err := json.Unmarshal(call("inventory", "diff", "-before", first.ID, "-after", second.ID), &changes); err != nil || len(changes) != 1 || changes[0].Type != "changed" {
		t.Fatal(changes, err)
	}
	var history []inventory.Summary
	if err := json.Unmarshal(call("inventory", "list", "-asset", asset["id"].(string)), &history); err != nil || len(history) != 2 || history[0].ID != second.ID || history[0].ComponentCount != 1 {
		t.Fatal(history, err)
	}
}
