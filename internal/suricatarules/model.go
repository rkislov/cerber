// SPDX-License-Identifier: Apache-2.0
// Package suricatarules defines immutable, authenticated IDS rule packages.
package suricatarules

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxRules = 64 << 20
const MaxCompressed = 8 << 20
const MaxVersions = 12
const MaxStorage = 64 << 20

var ErrInvalid = errors.New("invalid Suricata rules")
var ErrConflict = errors.New("Suricata revision conflict or bundle in use")
var ErrLimit = errors.New("Suricata catalog capacity reached")
var ErrNotFound = errors.New("Suricata bundle not found")

type Manifest struct {
	Format          string    `json:"format,omitempty"`
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Source          string    `json:"source"`
	EngineMajor     int       `json:"engine_major"`
	Count           int       `json:"count"`
	Bytes           int       `json:"bytes"`
	CompressedBytes int       `json:"compressed_bytes"`
	CreatedAt       time.Time `json:"created_at"`
	CreatedBy       string    `json:"created_by"`
	Signature       string    `json:"signature"`
}
type Bundle struct {
	Manifest Manifest
	Data     []byte
}
type Assignment struct {
	GroupID       string    `json:"group_id,omitempty"`
	GroupRevision int64     `json:"group_revision,omitempty"`
	Revision      int64     `json:"revision"`
	Bundle        Manifest  `json:"bundle"`
	PreviousID    string    `json:"previous_id,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
	UpdatedBy     string    `json:"updated_by"`
}
type Change struct {
	AgentID          string `json:"agent_id"`
	ExpectedRevision int64  `json:"expected_revision"`
	BundleID         string `json:"bundle_id"`
	Rollback         bool   `json:"rollback"`
}
type Status struct {
	Version     int       `json:"version"`
	EngineMajor int       `json:"engine_major"`
	Revision    int64     `json:"revision"`
	DesiredID   string    `json:"desired_id,omitempty"`
	AppliedID   string    `json:"applied_id,omitempty"`
	State       string    `json:"state"`
	Error       string    `json:"error,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func ValidID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && strings.ToLower(s) == s
}
func (s Status) Validate() error {
	if s.Version != 1 || s.EngineMajor < 0 || s.EngineMajor > 99 || s.Revision < 0 || s.Revision >= 1<<53 || s.UpdatedAt.IsZero() || len(s.Error) > 512 {
		return ErrInvalid
	}
	for _, id := range []string{s.DesiredID, s.AppliedID} {
		if id != "" && !ValidID(id) {
			return ErrInvalid
		}
	}
	switch s.State {
	case "unconfigured", "idle", "downloading", "testing", "reloading", "applied", "error", "rollback_failed":
	default:
		return ErrInvalid
	}
	return nil
}
func (m Manifest) SigningBytes() []byte { m.Signature = ""; b, _ := json.Marshal(m); return b }
func (m Manifest) Verify(key string) error {
	k, e := base64.StdEncoding.DecodeString(key)
	sig, se := base64.StdEncoding.DecodeString(m.Signature)
	if e != nil || se != nil || !validFormat(m.Format) || len(k) != ed25519.PublicKeySize || !ValidID(m.ID) || m.EngineMajor < 7 || m.EngineMajor > 8 || m.Count < 1 || m.Bytes < 1 || m.Bytes > MaxRules || m.CompressedBytes < 1 || m.CompressedBytes > MaxCompressed || !ed25519.Verify(k, m.SigningBytes(), sig) {
		return ErrInvalid
	}
	return nil
}
func (m *Manifest) Sign(key ed25519.PrivateKey) {
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, m.SigningBytes()))
}
func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

var header = regexp.MustCompile(`^(alert|drop|reject|rejectsrc|rejectdst|rejectboth|pass)\s+[^\r\n]+\([^\r\n]*\)\s*$`)
var sidRE = regexp.MustCompile(`^sid\s*:\s*([0-9]+)$`)
var revRE = regexp.MustCompile(`^rev\s*:\s*([0-9]+)$`)

// Normalize performs structural checks only. The target engine is the syntax
// authority. Quoted semicolons are not treated as option delimiters.
func Normalize(data []byte) ([]byte, int, error) {
	if len(data) > MaxRules || !utf8.Valid(data) || bytes.ContainsRune(data, 0) {
		return nil, 0, ErrInvalid
	}
	var out bytes.Buffer
	seen := map[uint64]bool{}
	count := 0
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > 65536 || !header.MatchString(line) {
			return nil, 0, fmt.Errorf("%w: line %d: one complete rule per line required", ErrInvalid, n+1)
		}
		options := line[strings.IndexByte(line, '(')+1 : strings.LastIndexByte(line, ')')]
		var parts []string
		start := 0
		quoted, escaped := false, false
		for k, c := range options {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				// PCRE character classes may contain unescaped quotes. A value
				// closes at its terminal quote immediately before ';'.
				if !quoted {
					quoted = true
				} else if strings.HasPrefix(strings.TrimSpace(options[k+1:]), ";") {
					quoted = false
				}
			}
			if c == ';' && !quoted {
				parts = append(parts, strings.TrimSpace(options[start:k]))
				start = k + 1
			}
		}
		if quoted || strings.TrimSpace(options[start:]) != "" {
			return nil, 0, fmt.Errorf("%w: line %d: unterminated option", ErrInvalid, n+1)
		}
		var sid, rev uint64
		for _, p := range parts {
			name := strings.ToLower(strings.TrimSpace(strings.SplitN(p, ":", 2)[0]))
			// Rules must not run Lua or read/write arbitrary local dataset files.
			switch name {
			case "lua", "luajit", "dataset", "datarep", "filemd5", "filesha1", "filesha256":
				return nil, 0, fmt.Errorf("%w: line %d: external scripts/data files are not supported", ErrInvalid, n+1)
			}
			if m := sidRE.FindStringSubmatch(p); m != nil {
				if sid != 0 {
					return nil, 0, ErrInvalid
				}
				var err error
				sid, err = strconv.ParseUint(m[1], 10, 32)
				if err != nil {
					return nil, 0, ErrInvalid
				}
			}
			if m := revRE.FindStringSubmatch(p); m != nil {
				if rev != 0 {
					return nil, 0, ErrInvalid
				}
				var err error
				rev, err = strconv.ParseUint(m[1], 10, 32)
				if err != nil || rev == 0 {
					return nil, 0, ErrInvalid
				}
			}
		}
		if sid == 0 || seen[sid] {
			return nil, 0, fmt.Errorf("%w: line %d: missing/duplicate SID or invalid rev", ErrInvalid, n+1)
		}
		seen[sid] = true
		count++
		out.WriteString(line)
		out.WriteByte('\n')
	}
	if count == 0 {
		return nil, 0, fmt.Errorf("%w: no enabled rules", ErrInvalid)
	}
	return out.Bytes(), count, nil
}
func Pack(name, source string, major int, data []byte) (Bundle, error) {
	return PackFiles(name, source, major, data, "")
}
func PackFiles(name, source string, major int, data []byte, classification string) (Bundle, error) {
	var b Bundle
	if strings.TrimSpace(name) == "" || len(name) > 120 || strings.ContainsAny(name, "\r\n\x00") || (source != "custom" && source != "et-open" && source != "combined" && source != "feed") || (major != 7 && major != 8) || ValidateClassification(classification) != nil {
		return b, ErrInvalid
	}
	normalized, count, e := Normalize(data)
	if e != nil {
		return b, e
	}
	var zipped bytes.Buffer
	w := gzip.NewWriter(&zipped)
	payload := normalized
	format := ""
	if classification != "" {
		format = filesFormat
		payload, e = json.Marshal(ruleFiles{Rules: string(normalized), Classification: classification})
		if e != nil {
			return b, e
		}
	}
	if _, e = w.Write(payload); e != nil {
		return b, e
	}
	if e = w.Close(); e != nil {
		return b, e
	}
	if zipped.Len() > MaxCompressed {
		return b, ErrLimit
	}
	b.Data = zipped.Bytes()
	b.Manifest = Manifest{Format: format, ID: DataID(major, b.Data), Name: name, Source: source, EngineMajor: major, Count: count, Bytes: len(normalized), CompressedBytes: len(b.Data)}
	return b, nil
}
func Unpack(m Manifest, data []byte) ([]byte, error) {
	rules, _, err := UnpackFiles(m, data)
	return rules, err
}
func UnpackFiles(m Manifest, data []byte) ([]byte, string, error) {
	if !validFormat(m.Format) || len(data) != m.CompressedBytes || len(data) > MaxCompressed || DataID(m.EngineMajor, data) != m.ID {
		return nil, "", ErrInvalid
	}
	r, e := gzip.NewReader(bytes.NewReader(data))
	if e != nil {
		return nil, "", ErrInvalid
	}
	defer r.Close()
	limit := MaxRules
	if m.Format != "" {
		limit = MaxRules*2 + MaxClassification*6 + 128
	}
	plain, e := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	classification := ""
	if e != nil || len(plain) > limit {
		return nil, "", ErrInvalid
	}
	if m.Format != "" {
		var files ruleFiles
		if json.Unmarshal(plain, &files) != nil || files.Classification == "" {
			return nil, "", ErrInvalid
		}
		plain, classification = []byte(files.Rules), files.Classification
	}
	if len(plain) != m.Bytes || len(plain) > MaxRules || ValidateClassification(classification) != nil {
		return nil, "", ErrInvalid
	}
	normalized, n, e := Normalize(plain)
	if e != nil || n != m.Count || !bytes.Equal(normalized, plain) {
		return nil, "", ErrInvalid
	}
	return plain, classification, nil
}

func DataID(major int, b []byte) string { return Hash(append([]byte(strconv.Itoa(major)+":"), b...)) }
