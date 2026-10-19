// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"encoding/json"
	"github.com/rkislov/cerber/internal/ingest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func configFixture(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	c := Config{SchemaVersion: 1, Database: filepath.Join(root, "agent.db"), AssetID: "local", Credentials: filepath.Join(root, "credentials.json"), Server: "https://siem.example", Interval: "1h"}
	data, _ := json.Marshal(ingest.Credentials{AgentID: "agent", Token: strings.Repeat("a", 64)})
	if err := os.WriteFile(c.Credentials, data, 0600); err != nil {
		t.Fatal(err)
	}
	return c
}
func TestConfigRejectsUnsafeOrAmbiguousSettings(t *testing.T) {
	base := configFixture(t)
	for _, mutate := range []func(*Config){func(c *Config) { c.Database = "relative.db" }, func(c *Config) { c.Database = "" }, func(c *Config) { c.Credentials = "" }, func(c *Config) { c.Database = c.Credentials }, func(c *Config) { c.Interval = "0s" }, func(c *Config) { c.RefreshPackageMetadata = true }, func(c *Config) { c.CheckWindowsUpdates = true; c.CheckPackageUpdates = true }, func(c *Config) { c.PackageManager = "shell" }, func(c *Config) { c.SchemaVersion = 2 }} {
		c := base
		mutate(&c)
		if c.Validate() == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}
func TestConfigValidationIsOfflineAndDoesNotCreateDatabase(t *testing.T) {
	c := configFixture(t)
	if err := c.ValidateInputs(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.Database); !os.IsNotExist(err) {
		t.Fatal("validation opened database", err)
	}
	file := filepath.Join(t.TempDir(), "agent.json")
	data, _ := json.Marshal(c)
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(file)
	if err != nil || loaded.Database != c.Database {
		t.Fatal(loaded, err)
	}
	if _, err = LoadConfig("relative.json"); err == nil {
		t.Fatal("accepted relative config")
	}
	data = append(data, []byte(` {}`)...)
	os.WriteFile(file, data, 0600)
	if _, err = LoadConfig(file); err == nil {
		t.Fatal("accepted trailing data")
	}
}
