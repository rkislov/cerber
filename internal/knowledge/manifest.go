// SPDX-License-Identifier: Apache-2.0
// Package knowledge distributes immutable signed raw knowledge packages.
// Parsing BDU records and matching software versions are separate responsibilities.
package knowledge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rkislov/cerber/internal/domain"
)

const MaxPackageBytes int64 = 512 << 20
const MaxManifestBytes int64 = 64 << 10

var versionPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

type Manifest struct {
	SchemaVersion int                      `json:"schema_version"`
	Snapshot      domain.KnowledgeSnapshot `json:"snapshot"`
	Sequence      uint64                   `json:"sequence"`
	PublishedAt   time.Time                `json:"published_at"`
	Size          int64                    `json:"size"`
	Format        string                   `json:"format"`
	Source        string                   `json:"source"`
}
type SignedManifest struct {
	Manifest  json.RawMessage `json:"manifest"`
	Signature string          `json:"signature"`
}

func (m Manifest) validate() error {
	if m.SchemaVersion != 1 || m.Sequence == 0 || m.PublishedAt.IsZero() || m.Format != "bdu-xml" {
		return fmt.Errorf("unsupported or incomplete knowledge manifest")
	}
	if !validVersion(m.Snapshot.Version) || m.Snapshot.ID != "bdu-"+m.Snapshot.Version {
		return fmt.Errorf("invalid package identity")
	}
	if m.Size < 1 || m.Size > MaxPackageBytes {
		return fmt.Errorf("package size must be between 1 and %d bytes", MaxPackageBytes)
	}
	if m.Source == "" || len(m.Source) > 2048 {
		return fmt.Errorf("package provenance is required")
	}
	if err := m.Snapshot.Validate(); err != nil {
		return err
	}
	if hex.EncodeToString(mustDecode(m.Snapshot.SHA256)) != m.Snapshot.SHA256 {
		return fmt.Errorf("digest must be lowercase hexadecimal")
	}
	return nil
}
func mustDecode(s string) []byte { b, _ := hex.DecodeString(s); return b }
func decode(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}
func Sign(m Manifest, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key")
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return json.Marshal(SignedManifest{Manifest: payload, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))})
}
func Verify(data []byte, key ed25519.PublicKey) (Manifest, error) {
	var m Manifest
	if int64(len(data)) > MaxManifestBytes || len(key) != ed25519.PublicKeySize {
		return m, fmt.Errorf("invalid manifest size or public key")
	}
	var signed SignedManifest
	if err := decode(data, &signed); err != nil {
		return m, err
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(key, signed.Manifest, signature) {
		return m, fmt.Errorf("knowledge manifest signature verification failed")
	}
	if err := decode(signed.Manifest, &m); err != nil {
		return m, err
	}
	return m, m.validate()
}
func ReadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(b)))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid base64 Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}
func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid base64 Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
func GenerateKeys(dir string) error {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	unlock, err := lock(dir)
	if err != nil {
		return err
	}
	defer unlock()
	// Never overwrite an existing identity, even if only one file survived a crash.
	for _, name := range []string{"signing.key", "signing.pub"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			return fmt.Errorf("key destination already exists or is inaccessible: %s", name)
		}
	}
	if err = writeAtomic(filepath.Join(dir, "signing.key"), []byte(base64.StdEncoding.EncodeToString(private.Seed())+"\n")); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, "signing.pub"), []byte(base64.StdEncoding.EncodeToString(public)+"\n"))
}
func digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

func newSnapshot(version, hash string) domain.KnowledgeSnapshot {
	return domain.KnowledgeSnapshot{ID: "bdu-" + version, Version: version, SHA256: hash}
}

// Reject Windows device names on every platform so a Linux publisher cannot
// produce an otherwise valid package that Windows clients cannot cache.
func validVersion(version string) bool {
	if !versionPattern.MatchString(version) {
		return false
	}
	base := strings.ToUpper(strings.SplitN(version, ".", 2)[0])
	switch base {
	case "CON", "PRN", "AUX", "NUL":
		return false
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
		return false
	}
	return true
}
