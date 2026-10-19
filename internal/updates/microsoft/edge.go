// SPDX-License-Identifier: Apache-2.0
package microsoft

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/inventory"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const EdgeFeedURL = "https://edgeupdates.microsoft.com/api/products?view=enterprise"

type EdgeClient struct {
	Client   *http.Client
	endpoint string
}
type edgeProduct struct {
	Product  string
	Releases []struct {
		Platform       string
		Architecture   string
		ProductVersion string
		PublishedTime  string
	}
}

// CompareVersion compares only numeric Windows product versions, not arbitrary
// application versions, SemVer, Debian epochs or RPM release identifiers.
func CompareVersion(a, b string) (int, error) {
	if len(a) > 512 || len(b) > 512 {
		return 0, fmt.Errorf("version exceeds 512 bytes")
	}
	parse := func(value string) ([4]uint32, error) {
		var v [4]uint32
		parts := strings.Split(value, ".")
		if len(parts) < 2 || len(parts) > 4 {
			return v, fmt.Errorf("expected 2–4 numeric version components")
		}
		for i, part := range parts {
			if part == "" {
				return v, fmt.Errorf("empty version component")
			}
			for _, c := range part {
				if c < '0' || c > '9' {
					return v, fmt.Errorf("unsupported version syntax")
				}
			}
			n, err := strconv.ParseUint(part, 10, 32)
			if err != nil {
				return v, err
			}
			v[i] = uint32(n)
		}
		return v, nil
	}
	av, err := parse(a)
	if err != nil {
		return 0, err
	}
	bv, err := parse(b)
	if err != nil {
		return 0, err
	}
	for i := range av {
		if av[i] < bv[i] {
			return -1, nil
		}
		if av[i] > bv[i] {
			return 1, nil
		}
	}
	return 0, nil
}

// Check uses an explicit inventory ID/channel/architecture binding. It never
// infers that an application is Microsoft Edge merely from its display name.
func (c EdgeClient) Check(ctx context.Context, component inventory.Component, channel, arch string) (inventory.Availability, error) {
	result := inventory.Availability{ComponentID: component.ID, InstalledVersion: component.Version, SourceURL: EdgeFeedURL, Channel: channel, Architecture: arch, Status: "unknown"}
	switch channel {
	case "Stable", "Beta", "Dev":
	default:
		return result, fmt.Errorf("supported Edge channels: Stable, Beta, Dev")
	}
	switch arch {
	case "x64", "x86", "arm64":
	default:
		return result, fmt.Errorf("Edge architecture must be explicit: x64, x86 or arm64")
	}
	endpoint := c.endpoint
	if endpoint == "" {
		endpoint = EdgeFeedURL
	}
	client := http.Client{Timeout: 30 * time.Second}
	if c.Client != nil {
		client = *c.Client
		if client.Timeout == 0 {
			client.Timeout = 30 * time.Second
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return result, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return result, fmt.Errorf("Microsoft Edge source returned HTTP %d", resp.StatusCode)
	}
	const maxBytes = 8 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return result, err
	}
	if len(data) > maxBytes {
		return result, fmt.Errorf("Edge metadata exceeds 8 MiB")
	}
	var products []edgeProduct
	if err = json.Unmarshal(data, &products); err != nil {
		return result, err
	}
	var available, published string
	now := time.Now()
	for _, p := range products {
		if p.Product != channel {
			continue
		}
		for _, r := range p.Releases {
			if !strings.EqualFold(r.Platform, "Windows") || r.Architecture != arch || releaseTime(r.PublishedTime).IsZero() || releaseTime(r.PublishedTime).After(now.Add(5*time.Minute)) {
				continue
			}
			if _, err := CompareVersion(r.ProductVersion, r.ProductVersion); err != nil {
				return result, fmt.Errorf("invalid Edge version in official metadata: %w", err)
			}
			if available == "" {
				available = r.ProductVersion
				published = r.PublishedTime
			} else {
				cmp, _ := CompareVersion(available, r.ProductVersion)
				if cmp < 0 {
					available = r.ProductVersion
					published = r.PublishedTime
				}
			}
		}
	}
	if available == "" {
		return result, fmt.Errorf("Edge source has no release for selected channel/platform/architecture")
	}
	result.AvailableVersion = available
	result.SourcePublishedAt = published
	cmp, err := CompareVersion(component.Version, available)
	if err != nil {
		result.Detail = "Installed version cannot be compared as a numeric Windows product version"
		return result, nil
	}
	switch {
	case cmp < 0:
		result.Status = "update_available"
	case cmp == 0:
		result.Status = "up_to_date"
	case cmp > 0:
		result.Status = "installed_newer_than_source"
	}
	result.Detail = "Release availability only; not a vulnerability finding or proof of deployment compatibility"
	return result, nil
}

// Microsoft's feed also emits ISO dates without a UTC offset. Preserve the raw
// value in results and interpret unqualified source timestamps as UTC here.
func releaseTime(value string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999"} {
		if t, err := time.Parse(layout, value); err == nil {
			return t
		}
	}
	return time.Time{}
}
