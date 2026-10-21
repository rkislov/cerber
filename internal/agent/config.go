// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/telemetry"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config contains deployment settings, never the bearer token itself. All paths
// are absolute so SCM/systemd working directories cannot redirect state or secrets.
type Config struct {
	EndpointState          string `json:"endpoint_state,omitempty"`
	EndpointKey            string `json:"endpoint_key,omitempty"`
	PatchInbox             string `json:"patch_inbox,omitempty"`
	PatchOutbox            string `json:"patch_outbox,omitempty"`
	EventSources           string `json:"event_sources,omitempty"`
	HeartbeatInterval      string `json:"heartbeat_interval,omitempty"`
	SchemaVersion          int    `json:"schema_version"`
	Database               string `json:"database"`
	AssetID                string `json:"asset_id"`
	Credentials            string `json:"credentials"`
	Server                 string `json:"server"`
	CACert                 string `json:"ca_cert,omitempty"`
	Interval               string `json:"interval"`
	CheckWindowsUpdates    bool   `json:"check_windows_updates"`
	CheckPackageUpdates    bool   `json:"check_package_updates"`
	RefreshPackageMetadata bool   `json:"refresh_package_metadata"`
	PackageManager         string `json:"package_manager,omitempty"`
}

func decodeFile(path string, limit int64, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return fmt.Errorf("configuration file exceeds size limit")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(value); err != nil {
		return fmt.Errorf("invalid configuration JSON")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fmt.Errorf("trailing configuration data")
	}
	return nil
}
func LoadCredentials(path string) (ingest.Credentials, error) {
	var c ingest.Credentials
	if err := decodeFile(path, 4096, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}
func LoadConfig(path string) (Config, error) {
	var c Config
	if !filepath.IsAbs(path) {
		return c, fmt.Errorf("agent config path must be absolute")
	}
	if err := decodeFile(path, 16<<10, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if (c.EndpointState == "") != (c.EndpointKey == "") {
		return fmt.Errorf("both endpoint paths required")
	}
	if c.EndpointState != "" && (!filepath.IsAbs(c.EndpointState) || !filepath.IsAbs(c.EndpointKey)) {
		return fmt.Errorf("absolute endpoint paths required")
	}
	if (c.PatchInbox == "") != (c.PatchOutbox == "") {
		return fmt.Errorf("both patch spool paths are required")
	}
	for _, p := range []string{c.PatchInbox, c.PatchOutbox} {
		if p != "" && (strings.HasPrefix(p, `\\`) || strings.ContainsAny(p, "\r\n\x00")) {
			return fmt.Errorf("patch spool requires local paths")
		}
	}
	if c.PatchInbox != "" && (!filepath.IsAbs(c.PatchInbox) || !filepath.IsAbs(c.PatchOutbox) || c.PatchInbox == c.PatchOutbox) {
		return fmt.Errorf("separate absolute patch spool directories required")
	}
	if c.EventSources != "" {
		seen := map[string]bool{}
		for _, source := range strings.Split(c.EventSources, ",") {
			if !telemetry.ValidSource(source) || seen[source] {
				return fmt.Errorf("invalid event sources")
			}
			seen[source] = true
		}
	}
	if c.HeartbeatInterval != "" {
		interval, err := time.ParseDuration(c.HeartbeatInterval)
		if err != nil || interval < time.Minute || interval > time.Hour {
			return fmt.Errorf("heartbeat interval must be 1m–1h")
		}
	}
	if c.SchemaVersion != 1 || strings.TrimSpace(c.AssetID) == "" || len(c.AssetID) > 256 {
		return fmt.Errorf("config requires schema version 1 and a local asset ID")
	}
	for i, path := range []string{c.Database, c.Credentials, c.CACert} {
		if i == 2 && path == "" {
			continue
		}
		if path == "" || !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) || strings.ContainsAny(path, "\r\n\x00") {
			return fmt.Errorf("agent paths must be absolute local paths")
		}
	}
	if c.Database == c.Credentials || c.Database == c.CACert {
		return fmt.Errorf("database must be separate from configuration inputs")
	}
	interval, err := time.ParseDuration(c.Interval)
	if err != nil || interval < time.Minute || interval > 24*time.Hour {
		return fmt.Errorf("interval must be 1m–24h")
	}
	if c.RefreshPackageMetadata && !c.CheckPackageUpdates {
		return fmt.Errorf("metadata refresh requires package update checking")
	}
	if c.CheckWindowsUpdates && (c.CheckPackageUpdates || c.RefreshPackageMetadata || c.PackageManager != "" && c.PackageManager != "auto") {
		return fmt.Errorf("Windows and Linux collection settings cannot be combined")
	}
	switch c.PackageManager {
	case "", "auto", "apt", "apt-rpm", "dnf", "yum":
	default:
		return fmt.Errorf("unknown package manager")
	}
	return nil
}

// ValidateInputs checks local credentials and CA syntax without contacting SIEM or
// opening/migrating the state database. Asset existence is checked when collection runs.
func (c Config) ValidateInputs() error {
	if err := c.Validate(); err != nil {
		return err
	}
	credentials, err := LoadCredentials(c.Credentials)
	if err != nil {
		return err
	}
	var ca []byte
	if c.CACert != "" {
		ca, err = os.ReadFile(c.CACert)
		if err != nil {
			return err
		}
	}
	client, err := ingest.NewClient(c.Server, credentials, ca)
	if err != nil {
		return err
	}
	client.Close()
	return nil
}
func (c Config) Args() []string {
	args := []string{"-db", c.Database, "agent", "run", "-asset", c.AssetID, "-credentials", c.Credentials, "-server", c.Server, "-interval", c.Interval}
	if c.HeartbeatInterval != "" {
		args = append(args, "-heartbeat-interval", c.HeartbeatInterval)
	}
	if c.EndpointState != "" {
		args = append(args, "-endpoint-state", c.EndpointState, "-endpoint-key", c.EndpointKey)
	}
	if c.PatchInbox != "" {
		args = append(args, "-patch-inbox", c.PatchInbox, "-patch-outbox", c.PatchOutbox)
	}
	if c.CACert != "" {
		args = append(args, "-ca-cert", c.CACert)
	}
	if c.EventSources != "" {
		args = append(args, "-event-sources", c.EventSources)
	}
	if c.CheckWindowsUpdates {
		args = append(args, "-check-windows-updates")
	}
	if c.CheckPackageUpdates {
		args = append(args, "-check-package-updates")
	}
	if c.RefreshPackageMetadata {
		args = append(args, "-refresh-package-metadata")
	}
	if c.PackageManager != "" {
		args = append(args, "-package-manager", c.PackageManager)
	}
	return args
}
