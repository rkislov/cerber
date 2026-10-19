// SPDX-License-Identifier: Apache-2.0
package knowledge

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type Repository struct{ Root string }

func (r Repository) packagePath(hash string) string {
	return filepath.Join(r.Root, "packages", hash+".xml")
}
func (r Repository) Latest() ([]byte, error) {
	f, err := os.Open(filepath.Join(r.Root, "latest.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readLimited(f, MaxManifestBytes)
}

// Publish never activates a manifest before its complete payload is synced.
// The caller supplies provenance; signing is a Cerber publisher signature,
// not an assertion that FSTEC signed the upstream XML.
func (r Repository) Publish(ctx context.Context, input io.Reader, version, source string, key ed25519.PrivateKey) (Manifest, error) {
	var empty Manifest
	if r.Root == "" || !versionPattern.MatchString(version) || len(key) != ed25519.PrivateKeySize {
		return empty, fmt.Errorf("valid version and signing key required")
	}
	if err := os.MkdirAll(filepath.Join(r.Root, "packages"), 0700); err != nil {
		return empty, err
	}
	if err := os.MkdirAll(filepath.Join(r.Root, "releases"), 0700); err != nil {
		return empty, err
	}
	unlock, err := lock(r.Root)
	if err != nil {
		return empty, err
	}
	defer unlock()
	release := filepath.Join(r.Root, "releases", version+".json")
	if _, err := os.Stat(release); !os.IsNotExist(err) {
		return empty, fmt.Errorf("version already published or inaccessible")
	}
	sequence := uint64(1)
	if previous, err := r.Latest(); err == nil {
		m, err := Verify(previous, key.Public().(ed25519.PublicKey))
		if err != nil {
			return empty, err
		}
		sequence = m.Sequence + 1
		if sequence == 0 {
			return empty, fmt.Errorf("sequence exhausted")
		}
	} else if !os.IsNotExist(err) {
		return empty, err
	}
	file, err := os.CreateTemp(filepath.Join(r.Root, "packages"), ".download-*")
	if err != nil {
		return empty, err
	}
	defer os.Remove(file.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(file, h), contextReader{ctx, io.LimitReader(input, MaxPackageBytes+1)})
	if err != nil {
		file.Close()
		return empty, err
	}
	if n < 1 || n > MaxPackageBytes {
		file.Close()
		return empty, fmt.Errorf("package size outside allowed limits")
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return empty, err
	}
	if err = file.Close(); err != nil {
		return empty, err
	}
	if err = validateXML(ctx, file.Name()); err != nil {
		return empty, err
	}
	m := Manifest{SchemaVersion: 1, Snapshot: newSnapshot(version, hex.EncodeToString(h.Sum(nil))), Sequence: sequence,
		PublishedAt: time.Now().UTC(), Size: n, Format: "bdu-xml", Source: source}
	signed, err := Sign(m, key)
	if err != nil {
		return empty, err
	}
	path := r.packagePath(m.Snapshot.SHA256)
	if _, err = os.Stat(path); err == nil {
		if err = verifyFile(ctx, path, m); err != nil {
			return empty, err
		}
	} else if os.IsNotExist(err) {
		if err = os.Rename(file.Name(), path); err != nil {
			return empty, err
		}
	} else {
		return empty, err
	}
	// Record the immutable release before moving the active pointer.
	if err = writeAtomic(release, signed); err != nil {
		return empty, err
	}
	if err = writeAtomic(filepath.Join(r.Root, "latest.json"), signed); err != nil {
		return empty, err
	}
	return m, nil
}
