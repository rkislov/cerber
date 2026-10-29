// SPDX-License-Identifier: Apache-2.0
package inventory

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

const MaxSnapshotBytes int64 = 32 << 20

// Coverage makes missing data explicit. A failed/partial collector cannot prove removal.
type Coverage struct {
	Section string `json:"section"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
}
type OS struct {
	RebootRequired   *bool    `json:"reboot_required,omitempty"`
	Release          string   `json:"release,omitempty"`
	InstallationType string   `json:"installation_type,omitempty"`
	CPEName          string   `json:"cpe_name,omitempty"`
	BranchID         string   `json:"branch_id,omitempty"`
	DistributionID   string   `json:"distribution_id,omitempty"`
	IDLike           []string `json:"id_like,omitempty"`
	Codename         string   `json:"codename,omitempty"`
	Kernel           string   `json:"kernel,omitempty"`
	Name             string   `json:"name"`
	Family           string   `json:"family"`
	Version          string   `json:"version"`
	Build            string   `json:"build"`
	Edition          string   `json:"edition,omitempty"`
	Architecture     string   `json:"architecture"`
}
type Component struct {
	SourcePackage     string   `json:"source_package,omitempty"`
	SourceVersion     string   `json:"source_version,omitempty"`
	VersionScheme     string   `json:"version_scheme,omitempty"`
	InstalledVersions []string `json:"installed_versions,omitempty"`
	State             string   `json:"state,omitempty"`
	ID                string   `json:"id"`
	Kind              string   `json:"kind"`
	Name              string   `json:"name"`
	Version           string   `json:"version"`
	Publisher         string   `json:"publisher,omitempty"`
	Architecture      string   `json:"architecture,omitempty"`
	Source            string   `json:"source"`
	ProductKey        string   `json:"product_key,omitempty"`
}
type Update struct {
	InstalledVersion  string   `json:"installed_version,omitempty"`
	InstalledVersions []string `json:"installed_versions,omitempty"`
	AvailableVersion  string   `json:"available_version,omitempty"`
	Architecture      string   `json:"architecture,omitempty"`
	Repository        string   `json:"repository,omitempty"`
	VersionScheme     string   `json:"version_scheme,omitempty"`
	ID                string   `json:"id"`
	Revision          int      `json:"revision"`
	Title             string   `json:"title"`
	KBs               []string `json:"kbs"`
	State             string   `json:"state"`
	Source            string   `json:"source"`
}
type Snapshot struct {
	PackageManager     string      `json:"package_manager,omitempty"`
	RepositoryMetadata string      `json:"repository_metadata,omitempty"`
	SchemaVersion      int         `json:"schema_version"`
	ID                 string      `json:"id"`
	AssetID            string      `json:"asset_id"`
	CollectedAt        time.Time   `json:"collected_at"`
	Collector          string      `json:"collector"`
	OS                 OS          `json:"os"`
	Coverage           []Coverage  `json:"coverage"`
	Components         []Component `json:"components"`
	Updates            []Update    `json:"updates"`
}

func section(kind string) string {
	switch kind {
	case "package":
		return "packages"
	case "application":
		return "applications"
	case "component":
		return "components"
	}
	return ""
}
func (s Snapshot) CoverageStatus(section string) string {
	for _, c := range s.Coverage {
		if c.Section == section {
			return c.Status
		}
	}
	return "unknown"
}
func text(s string, max int) bool { return strings.TrimSpace(s) != "" && len(s) <= max }
func (s Snapshot) Validate() error {
	if s.SchemaVersion != 1 || !text(s.ID, 256) || !text(s.AssetID, 256) || !text(s.Collector, 256) {
		return fmt.Errorf("inventory requires schema version 1, IDs and collector provenance")
	}
	if s.CollectedAt.IsZero() || s.CollectedAt.After(time.Now().Add(5*time.Minute)) {
		return fmt.Errorf("invalid inventory collection time")
	}
	if len(s.Components) > 100000 || len(s.Updates) > 100000 {
		return fmt.Errorf("inventory exceeds 100000 records per section")
	}
	if len(s.Coverage) < 1 || len(s.Coverage) > 6 {
		return fmt.Errorf("inventory must declare 1–6 coverage sections")
	}
	sections := map[string]bool{}
	for _, c := range s.Coverage {
		switch c.Section {
		case "os", "packages", "applications", "components", "updates_installed", "updates_available":
		default:
			return fmt.Errorf("unknown coverage section %q", c.Section)
		}
		switch c.Status {
		case "complete", "partial", "unsupported", "error", "not_requested":
		default:
			return fmt.Errorf("invalid coverage status")
		}
		if sections[c.Section] || len(c.Detail) > 4096 {
			return fmt.Errorf("duplicate coverage section or excessive detail")
		}
		sections[c.Section] = true
	}
	for _, field := range []struct {
		value string
		limit int
	}{{s.OS.Release, 64}, {s.OS.InstallationType, 64}, {s.OS.Name, 512}, {s.OS.Family, 64}, {s.OS.Version, 256}, {s.OS.Build, 256}, {s.OS.Edition, 256}, {s.OS.Architecture, 64}} {
		if len(field.value) > field.limit {
			return fmt.Errorf("OS metadata field exceeds length limit")
		}
	}
	if s.CoverageStatus("os") == "complete" && (!text(s.OS.Name, 512) || !text(s.OS.Version, 256) || !text(s.OS.Architecture, 64)) {
		return fmt.Errorf("complete OS section requires name, version and architecture")
	}
	if len(s.PackageManager) > 64 || len(s.RepositoryMetadata) > 64 || len(s.OS.CPEName) > 512 || len(s.OS.BranchID) > 64 || len(s.OS.DistributionID) > 256 || len(s.OS.Codename) > 256 || len(s.OS.Kernel) > 512 || len(s.OS.IDLike) > 32 {
		return fmt.Errorf("excessive Linux metadata")
	}
	for _, v := range s.OS.IDLike {
		if !text(v, 256) {
			return fmt.Errorf("invalid OS family")
		}
	}
	ids := map[string]bool{}
	for _, c := range s.Components {
		if section(c.Kind) == "" || !text(c.ID, 2048) || !text(c.Name, 1024) || !text(c.Source, 256) || len(c.Version) > 512 || len(c.SourcePackage) > 256 || len(c.SourceVersion) > 512 || len(c.ProductKey) > 2048 || len(c.Publisher) > 1024 || len(c.Architecture) > 64 || len(c.State) > 64 {
			return fmt.Errorf("invalid component")
		}
		if err := validateVersions(c.VersionScheme, c.InstalledVersions); err != nil {
			return err
		}
		status := s.CoverageStatus(section(c.Kind))
		if status != "complete" && status != "partial" {
			return fmt.Errorf("component has no collected coverage scope")
		}
		if ids[c.ID] {
			return fmt.Errorf("duplicate component ID %q", c.ID)
		}
		ids[c.ID] = true
	}
	ids = map[string]bool{}
	for _, u := range s.Updates {
		if err := validateVersions(u.VersionScheme, u.InstalledVersions); err != nil {
			return err
		}
		if len(u.InstalledVersion) > 512 || len(u.AvailableVersion) > 512 || len(u.Architecture) > 64 || len(u.Repository) > 1024 {
			return fmt.Errorf("excessive package update metadata")
		}
		scope := "updates_" + u.State
		if (u.State != "installed" && u.State != "available") || !text(u.ID, 2048) || !text(u.Source, 256) || len(u.Title) > 4096 || u.Revision < 0 || len(u.KBs) > 256 {
			return fmt.Errorf("invalid update record")
		}
		status := s.CoverageStatus(scope)
		if status != "complete" && status != "partial" {
			return fmt.Errorf("update has no collected coverage scope")
		}
		for _, kb := range u.KBs {
			if !text(kb, 64) {
				return fmt.Errorf("invalid KB identifier")
			}
		}
		key := u.State + ":" + u.ID
		if ids[key] {
			return fmt.Errorf("duplicate update identity")
		}
		ids[key] = true
	}
	return nil
}

type Change struct {
	Section string          `json:"section"`
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Before  json.RawMessage `json:"before,omitempty"`
	After   json.RawMessage `json:"after,omitempty"`
}

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

// Diff only calls a disappearance a removal when both snapshots cover the same
// section completely. An incomplete collector reports observations, never absence.
func Diff(before, after Snapshot) ([]Change, error) {
	if before.AssetID != after.AssetID {
		return nil, fmt.Errorf("inventory snapshots belong to different assets")
	}
	if after.CollectedAt.Before(before.CollectedAt) {
		return nil, fmt.Errorf("inventory comparison is reversed")
	}
	changes := []Change{}
	if (after.CoverageStatus("os") == "complete" || after.CoverageStatus("os") == "partial") && !reflect.DeepEqual(before.OS, after.OS) {
		kind := "observed"
		if before.CoverageStatus("os") == "complete" && after.CoverageStatus("os") == "complete" {
			kind = "changed"
		}
		changes = append(changes, Change{Section: "os", ID: "os", Type: kind, Before: raw(before.OS), After: raw(after.OS)})
	}
	type item struct {
		scope string
		value any
	}
	flatten := func(s Snapshot) map[string]item {
		m := map[string]item{}
		for _, c := range s.Components {
			m["component:"+c.ID] = item{section(c.Kind), c}
		}
		for _, u := range s.Updates {
			m["update:"+u.State+":"+u.ID] = item{"updates_" + u.State, u}
		}
		return m
	}
	old, new := flatten(before), flatten(after)
	for key, value := range new {
		previous, found := old[key]
		if !found {
			kind := "observed"
			if before.CoverageStatus(value.scope) == "complete" {
				kind = "added"
			}
			changes = append(changes, Change{Section: value.scope, ID: key, Type: kind, After: raw(value.value)})
		} else if !reflect.DeepEqual(previous.value, value.value) {
			changes = append(changes, Change{Section: value.scope, ID: key, Type: "changed", Before: raw(previous.value), After: raw(value.value)})
		}
	}
	for key, value := range old {
		if _, found := new[key]; !found && before.CoverageStatus(value.scope) == "complete" && after.CoverageStatus(value.scope) == "complete" {
			changes = append(changes, Change{Section: value.scope, ID: key, Type: "removed", Before: raw(value.value)})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Section == changes[j].Section {
			return changes[i].ID < changes[j].ID
		}
		return changes[i].Section < changes[j].Section
	})
	return changes, nil
}

// Availability is an update signal, never a CVE/BDU finding or an installation instruction.
type Availability struct {
	ComponentID       string `json:"component_id"`
	InstalledVersion  string `json:"installed_version"`
	AvailableVersion  string `json:"available_version,omitempty"`
	Status            string `json:"status"`
	SourcePublishedAt string `json:"source_published_at,omitempty"`
	SourceURL         string `json:"source_url"`
	Channel           string `json:"channel"`
	Architecture      string `json:"architecture"`
	Detail            string `json:"detail,omitempty"`
}
type Check struct {
	ID          string         `json:"id"`
	AssetID     string         `json:"asset_id"`
	InventoryID string         `json:"inventory_id"`
	CheckedAt   time.Time      `json:"checked_at"`
	Source      string         `json:"source"`
	Results     []Availability `json:"results"`
}

type Summary struct {
	ID             string     `json:"id"`
	AssetID        string     `json:"asset_id"`
	CollectedAt    time.Time  `json:"collected_at"`
	Collector      string     `json:"collector"`
	OS             OS         `json:"os"`
	Coverage       []Coverage `json:"coverage"`
	ComponentCount int        `json:"component_count"`
	UpdateCount    int        `json:"update_count"`
}

func (c Check) Validate() error {
	if !text(c.ID, 256) || !text(c.AssetID, 256) || !text(c.InventoryID, 256) || !text(c.Source, 256) || c.CheckedAt.IsZero() || c.CheckedAt.After(time.Now().Add(5*time.Minute)) || len(c.Results) > 1000 {
		return fmt.Errorf("invalid update check metadata")
	}
	for _, r := range c.Results {
		if !text(r.ComponentID, 2048) || len(r.InstalledVersion) > 512 || len(r.AvailableVersion) > 512 || len(r.SourceURL) > 2048 || len(r.Detail) > 4096 || len(r.Channel) > 64 || len(r.Architecture) > 64 || len(r.SourcePublishedAt) > 128 {
			return fmt.Errorf("invalid update availability metadata")
		}
		switch r.Status {
		case "unknown", "update_available", "up_to_date", "installed_newer_than_source", "source_error":
		default:
			return fmt.Errorf("invalid update availability status")
		}
	}
	return nil
}

func validateVersions(scheme string, versions []string) error {
	if scheme != "" && scheme != "rpm" && scheme != "debian" {
		return fmt.Errorf("unknown version scheme")
	}
	if len(versions) > 512 {
		return fmt.Errorf("too many installed versions")
	}
	seen := map[string]bool{}
	for _, v := range versions {
		if !text(v, 512) || seen[v] {
			return fmt.Errorf("invalid installed version set")
		}
		seen[v] = true
	}
	return nil
}
