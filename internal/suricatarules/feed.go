// SPDX-License-Identifier: Apache-2.0
package suricatarules

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const FeedOrigin = "https://feed.kislovs.ru"
const feedCatalogPath = "/feeds/v1/suricata/catalog.json"

var feedSources = []string{"et-open", "nmap", "trafficid", "feodo", "hunting"}

type FeedItem struct {
	ID           string `json:"id"`
	DownloadPath string `json:"download_path"`
	SHA256       string `json:"sha256"`
	RuleCount    int    `json:"rule_count"`
	Size         int    `json:"size_bytes"`
}
type FeedCatalog struct {
	Format  string     `json:"format"`
	Sources []FeedItem `json:"sources"`
}
type FeedClient struct {
	client *http.Client
	origin string
}

func NewFeedClient() *FeedClient {
	return &FeedClient{client: &http.Client{Timeout: 90 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, origin: FeedOrigin}
}
func (c *FeedClient) get(ctx context.Context, key, path string, limit int) ([]byte, error) {
	if key == "" {
		return nil, fmt.Errorf("Feed subscription key is not configured")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", c.origin+path, nil)
	if err != nil {
		return nil, ErrInvalid
	}
	req.Header.Set("User-Agent", "Cerber-SIEM/1")
	req.Header.Set("X-Api-Key", key)
	res, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Feed request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("Feed HTTP %d", res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, int64(limit)+1))
	if err != nil || len(b) > limit {
		return nil, fmt.Errorf("Feed response exceeds limit or is incomplete")
	}
	return b, nil
}
func parseFeedCatalog(b []byte, offline bool) (FeedCatalog, error) {
	var c FeedCatalog
	if json.Unmarshal(b, &c) != nil || c.Format != "security-feed-suricata-catalog-v1" || len(c.Sources) != len(feedSources) {
		return c, ErrInvalid
	}
	seen := map[string]bool{}
	for _, s := range c.Sources {
		known := false
		for _, id := range feedSources {
			if s.ID == id {
				known = true
			}
		}
		path := "/feeds/v1/suricata/" + s.ID + ".tar.gz"
		if offline {
			path = s.ID + ".tar.gz"
		}
		if !known || seen[s.ID] || s.DownloadPath != path || !ValidID(s.SHA256) || s.Size < 1 || s.Size > MaxCompressed || s.RuleCount < 0 {
			return c, ErrInvalid
		}
		seen[s.ID] = true
	}
	return c, nil
}
func (c *FeedClient) Catalog(ctx context.Context, key string) (FeedCatalog, error) {
	b, err := c.get(ctx, key, "/feeds/v1/catalog.json", 64<<10)
	if err != nil {
		return FeedCatalog{}, err
	}
	var root struct {
		Project  string `json:"project"`
		Suricata string `json:"suricata_rules"`
	}
	if json.Unmarshal(b, &root) != nil || root.Project != "cerber" || root.Suricata != feedCatalogPath {
		return FeedCatalog{}, fmt.Errorf("Feed does not advertise the Cerber Suricata catalog")
	}
	b, err = c.get(ctx, key, feedCatalogPath, 64<<10)
	if err != nil {
		return FeedCatalog{}, err
	}
	return parseFeedCatalog(b, false)
}
func assembleFeed(c FeedCatalog, read func(FeedItem) ([]byte, error)) (Bundle, error) {
	var combined bytes.Buffer
	classification := ""
	count := 0
	for _, id := range feedSources {
		var item FeedItem
		for _, s := range c.Sources {
			if s.ID == id {
				item = s
			}
		}
		archive, err := read(item)
		if err != nil {
			return Bundle{}, err
		}
		if len(archive) != item.Size || Hash(archive) != item.SHA256 {
			return Bundle{}, fmt.Errorf("Feed %s archive checksum/size mismatch", item.ID)
		}
		rules, classes, err := ExtractETFiles(archive)
		if err != nil {
			return Bundle{}, fmt.Errorf("Feed %s: %w", item.ID, err)
		}
		_, n, err := Normalize(rules)
		if item.RuleCount == 0 && item.ID == "feodo" {
			n, err = 0, nil
			for _, line := range strings.Split(string(rules), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					err = ErrInvalid
					break
				}
			}
		}
		if err != nil || n != item.RuleCount {
			return Bundle{}, fmt.Errorf("Feed %s rule count/content mismatch: %v", item.ID, err)
		}
		if item.ID == "et-open" {
			classification = classes
		}
		if combined.Len()+len(rules) > MaxRules {
			return Bundle{}, ErrLimit
		}
		combined.Write(rules)
		combined.WriteByte('\n')
		count += n
	}
	if classification == "" {
		return Bundle{}, fmt.Errorf("Feed ET Open classification.config is required")
	}
	b, err := PackFiles("Feed · ET Open, Nmap, Traffic ID, Feodo, Hunting", "feed", 8, combined.Bytes(), classification)
	if err == nil && b.Manifest.Count != count {
		return Bundle{}, ErrInvalid
	}
	return b, err
}
func (c *FeedClient) Download(ctx context.Context, key string, major int) (Bundle, error) {
	if major != 8 {
		return Bundle{}, fmt.Errorf("Feed rules require Suricata 8; upgrade the sensor first")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	defer c.client.CloseIdleConnections()
	catalog, err := c.Catalog(ctx, key)
	if err != nil {
		return Bundle{}, err
	}
	return assembleFeed(catalog, func(s FeedItem) ([]byte, error) { return c.get(ctx, key, s.DownloadPath, MaxCompressed) })
}

// ImportFeedZIP reads only the five Suricata archives and their hashed catalog.
// The project ZIP's potentially large IOC export is never decompressed here.
func ImportFeedZIP(r io.ReaderAt, size int64) (Bundle, error) {
	if size < 1 || size > 512<<20 {
		return Bundle{}, ErrLimit
	}
	z, err := zip.NewReader(r, size)
	if err != nil || len(z.File) > 32 {
		return Bundle{}, ErrInvalid
	}
	files := map[string]*zip.File{}
	for _, f := range z.File {
		if files[f.Name] != nil || !f.Mode().IsRegular() {
			return Bundle{}, ErrInvalid
		}
		files[f.Name] = f
	}
	read := func(name string, limit int) ([]byte, error) {
		f := files[name]
		if f == nil || f.UncompressedSize64 > uint64(limit) {
			return nil, ErrInvalid
		}
		s, err := f.Open()
		if err != nil {
			return nil, ErrInvalid
		}
		defer s.Close()
		b, err := io.ReadAll(io.LimitReader(s, int64(limit)+1))
		if err != nil || len(b) > limit {
			return nil, ErrInvalid
		}
		return b, nil
	}
	b, err := read("manifest.json", 64<<10)
	if err != nil {
		return Bundle{}, err
	}
	var manifest struct {
		Format  string `json:"format"`
		Project string `json:"project"`
		Files   map[string]struct {
			SHA256 string `json:"sha256"`
			Bytes  int    `json:"bytes"`
		} `json:"files"`
	}
	if json.Unmarshal(b, &manifest) != nil || manifest.Format != "security-feed-project-v1" || manifest.Project != "cerber" {
		return Bundle{}, ErrInvalid
	}
	checked := func(name string, limit int) ([]byte, error) {
		b, e := read(name, limit)
		m := manifest.Files[name]
		if e != nil || len(b) != m.Bytes || Hash(b) != m.SHA256 {
			return nil, ErrInvalid
		}
		return b, nil
	}
	b, err = checked("suricata/catalog.json", 64<<10)
	if err != nil {
		return Bundle{}, err
	}
	c, err := parseFeedCatalog(b, true)
	if err != nil {
		return Bundle{}, err
	}
	return assembleFeed(c, func(s FeedItem) ([]byte, error) { return checked("suricata/"+s.DownloadPath, MaxCompressed) })
}
