// SPDX-License-Identifier: Apache-2.0
package endpoint

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"github.com/rkislov/cerber/internal/integrations"
	"github.com/rkislov/cerber/internal/telemetry"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type scanResult struct {
	Cursor, State, Error string
	Scanned, Skipped     int
	Findings             []Finding
}

func scanFiles(ctx context.Context, p Policy, iocs []integrations.IOC, cursor string) scanResult {
	return scanWithRoots(ctx, p, iocs, cursor, scanRoots(), scanExclusions())
}
func scanWithRoots(ctx context.Context, p Policy, iocs []integrations.IOC, cursor string, roots, systemExclude []string) scanResult {
	r := scanResult{Cursor: cursor, State: "running", Findings: []Finding{}}
	sha, md := map[string]string{}, map[string]string{}
	for _, v := range iocs {
		switch v.Type {
		case "sha256_hash":
			sha[strings.ToLower(v.Value)] = v.ID
		case "md5_hash":
			md[strings.ToLower(v.Value)] = v.ID
		}
	}
	excluded := append(systemExclude, p.Exclude...)
	var bytesRead int64
	stop := false
	for _, root := range roots {
		if stop {
			break
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
			if e != nil {
				r.Skipped++
				return nil
			}
			for _, x := range excluded {
				if path == x || strings.HasPrefix(path, strings.TrimRight(x, string(os.PathSeparator))+string(os.PathSeparator)) {
					if d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
			}
			if ctx.Err() != nil {
				stop = true
				return fs.SkipAll
			}
			if d.IsDir() {
				if path < cursor && !strings.HasPrefix(cursor, path+string(os.PathSeparator)) && path != root {
					return fs.SkipDir
				}
				return nil
			}
			if path <= cursor {
				return nil
			}
			if ctx.Err() != nil || r.Scanned >= 300 || bytesRead >= 512<<20 || len(r.Findings) >= 100 {
				stop = true
				return fs.SkipAll
			}
			r.Cursor = path
			if !d.Type().IsRegular() {
				r.Skipped++
				return nil
			}
			info, e := d.Info()
			if e != nil || info.Size() > 128<<20 {
				r.Skipped++
				return nil
			}
			f, e := os.Open(path)
			if e != nil {
				r.Skipped++
				return nil
			}
			after, e := f.Stat()
			if e != nil || !after.Mode().IsRegular() || !os.SameFile(info, after) {
				f.Close()
				r.Skipped++
				return nil
			}
			a, b := sha256.New(), md5.New()
			n, e := io.Copy(io.MultiWriter(a, b), io.LimitReader(f, 128<<20+1))
			end, statErr := f.Stat()
			f.Close()
			bytesRead += n
			if e != nil || n != info.Size() || statErr != nil || end.Size() != info.Size() || !end.ModTime().Equal(info.ModTime()) {
				r.Skipped++
				return nil
			}
			r.Scanned++
			sh, mh := hex.EncodeToString(a.Sum(nil)), hex.EncodeToString(b.Sum(nil))
			ioc := sha[sh]
			if ioc == "" {
				ioc = md[mh]
			}
			if ioc != "" {
				r.Findings = append(r.Findings, Finding{ID: telemetry.ID("file-ioc/1", path, sh, ioc, time.Now().UTC().String()), Path: path, SHA256: sh, MD5: mh, IOC: ioc, At: time.Now().UTC()})
			}
			return nil
		})
	}
	if !stop {
		r.Cursor = ""
		r.State = "completed"
	} else {
		r.State = "partial"
	}
	if len(sha) == 0 && len(md) == 0 {
		r.State = "no_hash_indicators"
	}
	return r
}
