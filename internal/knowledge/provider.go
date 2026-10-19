// SPDX-License-Identifier: Apache-2.0
package knowledge

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/ports"
)

// Provider implements a strict online refresh or an explicit offline cache read.
// It never falls back to cached data after an online error without caller consent.
type Provider struct {
	URL       string
	Token     string
	PublicKey ed25519.PublicKey
	CacheDir  string
	MaxAge    time.Duration
	Offline   bool
	Client    *http.Client
}

var _ ports.KnowledgeProvider = Provider{}

func (p Provider) Acquire(ctx context.Context) (domain.KnowledgeSnapshot, error) {
	m, err := p.Sync(ctx)
	return m.Snapshot, err
}
func (p Provider) Sync(ctx context.Context) (Manifest, error) {
	var empty Manifest
	if len(p.PublicKey) != ed25519.PublicKeySize || p.CacheDir == "" || p.MaxAge <= 0 {
		return empty, fmt.Errorf("public key, cache directory and positive maximum age are required")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := os.MkdirAll(filepath.Join(p.CacheDir, "packages"), 0700); err != nil {
		return empty, err
	}
	unlock, err := lock(p.CacheDir)
	if err != nil {
		return empty, err
	}
	defer unlock()
	latest := filepath.Join(p.CacheDir, "latest.json")
	var previous *Manifest
	if f, err := os.Open(latest); err == nil {
		data, readErr := readLimited(f, MaxManifestBytes)
		f.Close()
		if readErr != nil {
			return empty, readErr
		}
		m, err := Verify(data, p.PublicKey)
		if err != nil {
			return empty, fmt.Errorf("invalid cached manifest: %w", err)
		}
		previous = &m
	} else if !os.IsNotExist(err) {
		return empty, err
	}
	if p.Offline {
		if previous == nil {
			return empty, fmt.Errorf("offline cache is empty")
		}
		if err := p.fresh(*previous); err != nil {
			return empty, err
		}
		if err := verifyFile(ctx, filepath.Join(p.CacheDir, "packages", previous.Snapshot.SHA256+".xml"), *previous); err != nil {
			return empty, err
		}
		return *previous, nil
	}
	base, err := url.Parse(p.URL)
	if err != nil {
		return empty, fmt.Errorf("invalid knowledge server URL")
	}
	if err = ValidateURL(base); err != nil {
		return empty, err
	}
	if len(p.Token) < 24 {
		return empty, fmt.Errorf("knowledge server token is required (at least 24 characters)")
	}
	client := http.Client{Timeout: 10 * time.Minute}
	if p.Client != nil {
		client = *p.Client
		if client.Timeout == 0 {
			client.Timeout = 10 * time.Minute
		}
	}
	// Never forward credentials to a redirect target, even on the same hostname.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	get := func(path string) (*http.Response, error) {
		endpoint := *base
		endpoint.Path = path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+p.Token)
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("knowledge request failed: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("knowledge server returned HTTP %d", resp.StatusCode)
		}
		return resp, nil
	}
	resp, err := get("/v1/knowledge/latest")
	if err != nil {
		return empty, err
	}
	data, err := readLimited(resp.Body, MaxManifestBytes)
	resp.Body.Close()
	if err != nil {
		return empty, err
	}
	m, err := Verify(data, p.PublicKey)
	if err != nil {
		return empty, err
	}
	if err = p.fresh(m); err != nil {
		return empty, err
	}
	if previous != nil {
		if m.Sequence < previous.Sequence {
			return empty, fmt.Errorf("knowledge rollback rejected")
		}
		if m.Sequence == previous.Sequence && m != *previous {
			return empty, fmt.Errorf("knowledge sequence reused for a different manifest")
		}
	}
	path := filepath.Join(p.CacheDir, "packages", m.Snapshot.SHA256+".xml")
	if err := verifyFile(ctx, path, m); err != nil {
		// Re-fetch and verify a missing or corrupt cached blob. No manifest is activated until this succeeds.
		resp, err := get("/v1/knowledge/packages/" + m.Snapshot.SHA256)
		if err != nil {
			return empty, err
		}
		err = p.download(ctx, path, resp.Body, m)
		resp.Body.Close()
		if err != nil {
			return empty, err
		}
	}
	releases := filepath.Join(p.CacheDir, "releases")
	if err = os.MkdirAll(releases, 0700); err != nil {
		return empty, err
	}
	release := filepath.Join(releases, m.Snapshot.Version+".json")
	if f, err := os.Open(release); err == nil {
		oldData, readErr := readLimited(f, MaxManifestBytes)
		f.Close()
		if readErr != nil {
			return empty, readErr
		}
		old, err := Verify(oldData, p.PublicKey)
		if err != nil {
			return empty, err
		}
		if old != m {
			return empty, fmt.Errorf("immutable knowledge version was changed")
		}
	} else if os.IsNotExist(err) {
		if err = writeAtomic(release, data); err != nil {
			return empty, err
		}
	} else {
		return empty, err
	}
	if err = writeAtomic(latest, data); err != nil {
		return empty, err
	}
	return m, nil
}
func (p Provider) fresh(m Manifest) error {
	now := time.Now().UTC()
	if m.PublishedAt.After(now.Add(5 * time.Minute)) {
		return fmt.Errorf("knowledge manifest is in the future")
	}
	if now.Sub(m.PublishedAt) > p.MaxAge {
		return fmt.Errorf("knowledge package exceeds maximum age %s", p.MaxAge)
	}
	return nil
}
func (p Provider) download(ctx context.Context, path string, input io.Reader, m Manifest) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".download-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), contextReader{ctx, io.LimitReader(input, m.Size+1)})
	if err != nil {
		f.Close()
		return err
	}
	if n != m.Size || hex.EncodeToString(h.Sum(nil)) != m.Snapshot.SHA256 {
		f.Close()
		return fmt.Errorf("downloaded package size or SHA-256 mismatch")
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// ValidateURL permits plaintext only for explicit loopback IPs. A URL contains no
// embedded credentials, prefix, query or fragment; clients use fixed API paths.
func ValidateURL(u *url.URL) error {
	if u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("knowledge URL must be a server origin without credentials or extra components")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		if ip, err := netip.ParseAddr(u.Hostname()); err == nil && ip.Unmap().IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("knowledge server requires HTTPS; HTTP is allowed only for a literal loopback IP")
}
