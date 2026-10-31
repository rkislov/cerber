// SPDX-License-Identifier: Apache-2.0
package eventcollector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/telemetry"
	"os"
	"path/filepath"
	"strings"
)

// ManagedEVE keeps at most current + one unread generation. A generation can
// only be deleted after the durable spool cursor has moved to its successor.
// A fsynced intent makes interrupted rename/reopen recoverable before any reads.
// The capture process must enforce a per-file hard size limit independently.
type ManagedEVE struct {
	RotatingLineFile
	RotateBytes int64
	Reopen      func(context.Context) error
}

func regularID(path string) (string, int64, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return "", 0, e
	}
	if !st.Mode().IsRegular() {
		return "", 0, fmt.Errorf("EVE must be a regular file")
	}
	f, e := os.Open(path)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	id, e := lineFileID(f)
	return id, st.Size(), e
}
func syncEVEDir(path string) error { return syncDirectory(filepath.Dir(path)) }
func (f ManagedEVE) Read(ctx context.Context, cursor string) ([]telemetry.Raw, error) {
	if f.RotateBytes < 1 || f.Reopen == nil {
		return nil, telemetry.ErrInvalid
	}
	marker := f.Path + ".rotate-pending"
	pending, e := os.ReadFile(marker)
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	if len(pending) > 1024 {
		return nil, telemetry.ErrInvalid
	}
	if len(pending) == 0 {
		id, size, e := regularID(f.Path)
		if e != nil {
			return nil, e
		}
		if size >= f.RotateBytes && strings.HasPrefix(cursor, "r1.") {
			var saved rotationCursor
			b, e := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(cursor, "r1."))
			if e != nil || json.Unmarshal(b, &saved) != nil {
				return nil, telemetry.ErrInvalid
			}
			if saved.File == id {
				if _, _, e = regularID(f.Path + ".1"); e == nil {
					if e = os.Remove(f.Path + ".1"); e != nil {
						return nil, e
					}
				} else if !os.IsNotExist(e) {
					return nil, e
				}
				h, e := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if e != nil {
					return nil, e
				}
				_, e = h.WriteString(id)
				if e == nil {
					e = h.Sync()
				}
				ce := h.Close()
				if e == nil {
					e = ce
				}
				if e != nil {
					return nil, e
				}
				if e = syncEVEDir(marker); e != nil {
					return nil, e
				}
				pending = []byte(id)
			}
		}
	}
	if len(pending) > 0 {
		oldID, _, oldErr := regularID(f.Path + ".1")
		if oldErr != nil || oldID != string(pending) {
			id, _, e := regularID(f.Path)
			if e != nil || id != string(pending) {
				return nil, fmt.Errorf("EVE rotation intent does not match a generation")
			}
			if !os.IsNotExist(oldErr) {
				return nil, fmt.Errorf("unexpected EVE rotation target")
			}
			if e = os.Rename(f.Path, f.Path+".1"); e != nil {
				return nil, e
			}
			if e = syncEVEDir(f.Path); e != nil {
				return nil, e
			}
		}
		if e = f.Reopen(ctx); e != nil {
			return nil, fmt.Errorf("EVE reopen failed; intent and cursor retained: %w", e)
		}
		id, _, e := regularID(f.Path)
		if e != nil || id == string(pending) {
			return nil, fmt.Errorf("EVE new generation not ready")
		}
		if e = os.Remove(marker); e != nil {
			return nil, e
		}
		if e = syncEVEDir(marker); e != nil {
			return nil, e
		}
	}
	return f.RotatingLineFile.Read(ctx, cursor)
}
