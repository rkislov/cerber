// SPDX-License-Identifier: Apache-2.0
package endpoint

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/integrations"
	"github.com/rkislov/cerber/internal/patch"
	"github.com/rkislov/cerber/internal/telemetry"
	"os"
	"path/filepath"
	"time"
)

type Client interface {
	EndpointExchange(context.Context, Report) (Signed, error)
}
type localState struct {
	Signed      Signed             `json:"signed"`
	IOCs        []integrations.IOC `json:"-"`
	FeedVersion string             `json:"feed_version"`
	Blocks      []Block            `json:"blocks"`
	Report      Report             `json:"report"`
	Cursor      string             `json:"cursor"`
	NextScan    time.Time          `json:"next_scan"`
	NextFeed    time.Time          `json:"next_feed"`
	NextSync    time.Time          `json:"next_sync"`
}
type Local struct {
	path  string
	key   ed25519.PublicKey
	agent string
	state localState
}

func OpenLocal(path, keyPath, agent string) (*Local, error) {
	if !filepath.IsAbs(path) || !filepath.IsAbs(keyPath) {
		return nil, ErrInvalid
	}
	if e := patch.ProtectExecutorConfig(keyPath); e != nil {
		return nil, e
	}
	key, e := patch.Public(keyPath)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	if st, e := os.Lstat(path); e == nil && (!st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0) {
		return nil, ErrInvalid
	}
	if e := patch.ProtectExecutorConfig(filepath.Dir(path)); e != nil {
		return nil, e
	}
	l := &Local{path: path, key: key, agent: agent}
	data, e := os.ReadFile(path)
	if e == nil {
		if len(data) > 128<<20 || json.Unmarshal(data, &l.state) != nil {
			return nil, ErrInvalid
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if l.state.FeedVersion != "" && !telemetry.Identifier(l.state.FeedVersion) {
		return nil, ErrInvalid
	}
	if l.state.FeedVersion != "" {
		b, e := os.ReadFile(path + ".ioc." + l.state.FeedVersion)
		if e != nil || len(b) > 128<<20 || json.Unmarshal(b, &l.state.IOCs) != nil {
			return nil, fmt.Errorf("IOC cache missing")
		}
	}
	if l.state.FeedVersion != "" && snapshotID(l.state.IOCs) != l.state.FeedVersion {
		return nil, fmt.Errorf("IOC cache integrity failed")
	}
	return l, nil
}
func (l *Local) save() error {
	data, e := json.Marshal(l.state)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(l.path), ".endpoint-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(data); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, l.path)
}
func (l *Local) Step(ctx context.Context, client Client) error {
	now := time.Now().UTC()
	desired := []Block{}
	b, valid := l.state.Signed.Verify(l.key, l.agent, now)
	if valid == nil && b.Policy.Mode == "confirm" {
		desired = b.Blocks
	}
	if l.state.Report.Blocks == nil {
		l.state.Report.Blocks = map[string]string{}
	}
	keep := []Block{}
	for _, old := range l.state.Blocks {
		found := false
		for _, d := range desired {
			if d.ID == old.ID && now.Before(d.Expires) {
				found = true
			}
		}
		if !found {
			if e := firewall(ctx, old, false); e != nil {
				keep = append(keep, old)
				l.state.Report.Blocks[old.ID] = "rollback_failed"
			} else {
				l.state.Report.Blocks[old.ID] = "removed"
			}
		} else {
			keep = append(keep, old)
		}
	}
	l.state.Blocks = keep
	if valid == nil {
		for _, d := range desired {
			if !now.Before(d.Expires) {
				continue
			}
			exists := false
			for _, old := range l.state.Blocks {
				if old.ID == d.ID {
					exists = true
				}
			}
			if !exists {
				l.state.Blocks = append(l.state.Blocks, d)
				if e := l.save(); e != nil {
					return e
				}
			}
			if e := firewall(ctx, d, true); e != nil {
				l.state.Report.Blocks[d.ID] = "apply_failed"
			} else {
				l.state.Report.Blocks[d.ID] = "applied"
			}
		}
	}
	if e := l.save(); e != nil {
		return e
	}
	// Transport failure does not prevent local expiry processing above.
	if !now.Before(l.state.NextSync) {
		l.state.Report.At = now
		l.state.Report.FeedVersion = l.state.FeedVersion
		l.state.Report.WantFeed = l.state.FeedVersion == "" || !now.Before(l.state.NextFeed)
		s, e := client.EndpointExchange(ctx, l.state.Report)
		if e != nil {
			return e
		}
		next, e := s.Verify(l.key, l.agent, time.Now().UTC())
		if e != nil {
			return e
		}
		if next.IOCs != nil {
			if snapshotID(next.IOCs) != next.FeedVersion && next.FeedVersion != "" {
				return fmt.Errorf("IOC bundle digest mismatch")
			}
			l.state.NextFeed = now.Add(time.Duration(next.Policy.SyncMinutes) * time.Minute)
			data, _ := json.Marshal(next.IOCs)
			if next.FeedVersion != "" {
				if e := writeBlob(l.path+".ioc."+next.FeedVersion, data); e != nil {
					return e
				}
			}
			l.state.IOCs = next.IOCs
			l.state.FeedVersion = next.FeedVersion
		} else if next.FeedVersion != l.state.FeedVersion {
			return fmt.Errorf("IOC snapshot missing")
		}
		if b.Policy.ID != next.Policy.ID || b.Policy.Version != next.Policy.Version {
			l.state.Cursor = ""
			l.state.NextScan = time.Time{}
		}
		if valid == nil && next.Issued.Before(b.Issued) {
			return fmt.Errorf("endpoint replay rejected")
		}
		if l.state.Report.WantFeed {
			l.state.NextFeed = now.Add(time.Duration(next.Policy.SyncMinutes) * time.Minute)
		}
		l.state.Signed = s
		l.state.Report.Findings = nil
		l.state.Report.Blocks = map[string]string{}
		l.state.Report.PolicyVersion = next.Policy.Version
		l.state.NextSync = now.Add(time.Minute)
		if e = l.save(); e != nil {
			return e
		}
		b = next
		valid = nil
	}
	if valid == nil && b.Policy.Scan && !now.Before(l.state.NextScan) && len(l.state.Report.Findings) == 0 {
		if l.state.Cursor == "" && l.state.NextScan.IsZero() && now.Hour() != b.Policy.ScanHourUTC {
			return nil
		}
		scanCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		result := scanFiles(scanCtx, b.Policy, l.state.IOCs, l.state.Cursor)
		cancel()
		l.state.Cursor = result.Cursor
		l.state.Report.Scanned += result.Scanned
		l.state.Report.Skipped += result.Skipped
		l.state.Report.ScanState = result.State
		l.state.Report.Error = result.Error
		l.state.Report.Findings = result.Findings
		if result.Cursor == "" {
			l.state.NextScan = now.Add(time.Duration(b.Policy.ScanIntervalMinutes) * time.Minute)
		}
		return l.save()
	}
	return nil
}

func snapshotID(items []integrations.IOC) string {
	b, _ := json.Marshal(items)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func writeBlob(path string, data []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".ioc-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(data); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(name, path)
}
