// SPDX-License-Identifier: Apache-2.0
package eventcollector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/telemetry"
	"os"
	"strconv"
	"strings"
	"time"
)

// RotatingLineFile follows rename rotation Path.1 ... Path.32, oldest first.
// Rotated files must be immutable, uncompressed and retained until drained.
// copytruncate and missing generations fail closed with the durable cursor intact.
type RotatingLineFile struct{ LineFile }
type rotationCursor struct {
	File string `json:"f"`
	Line string `json:"l"`
}

func (f RotatingLineFile) Read(ctx context.Context, cursor string) ([]telemetry.Raw, error) {
	var saved rotationCursor
	legacy := cursor != "" && !strings.HasPrefix(cursor, "r1.")
	if cursor != "" && !legacy {
		p, e := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(cursor, "r1."))
		if e != nil || len(p) > 1024 || json.Unmarshal(p, &saved) != nil || saved.File == "" || saved.Line == "" {
			return nil, telemetry.ErrInvalid
		}
	}
	if legacy {
		saved.Line = cursor
	}
	var file *os.File
	rank := 0
	for n := 0; n <= 32; n++ {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		path := f.Path
		if n > 0 {
			path += "." + strconv.Itoa(n)
		}
		st, e := os.Lstat(path)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return nil, e
		}
		if !st.Mode().IsRegular() {
			continue
		}
		v, e := os.Open(path)
		if e != nil {
			return nil, e
		}
		id, e := lineFileID(v)
		if e != nil {
			v.Close()
			return nil, e
		}
		match := saved.File == id || cursor == "" && n == 0
		if legacy {
			_, e = f.LineFile.readOpen(ctx, saved.Line, v)
			match = e == nil
		}
		if match {
			file = v
			rank = n
			break
		}
		v.Close()
	}
	if file == nil {
		return nil, fmt.Errorf("EVE file generation unavailable; cursor retained")
	}
	defer func() { file.Close() }()
	for transitions := 0; transitions <= 32; transitions++ {
		id, e := lineFileID(file)
		if e != nil {
			return nil, e
		}
		rows, e := f.LineFile.readOpen(ctx, saved.Line, file)
		if e != nil {
			return nil, e
		}
		if len(rows) > 0 {
			for k := range rows {
				next := rotationCursor{id, rows[k].Cursor}
				b, _ := json.Marshal(next)
				rows[k].Cursor = "r1." + base64.RawURLEncoding.EncodeToString(b)
				rows[k].ID = telemetry.ID(f.Path, f.Identity, rows[k].Cursor, string(rows[k].Data))
			}
			return rows, nil
		}
		if rank == 0 {
			return rows, nil
		}
		st, e := file.Stat()
		if e != nil {
			return nil, e
		}
		offset := int64(0)
		if saved.Line != "" {
			offset, e = strconv.ParseInt(strings.Split(saved.Line, ":")[0], 10, 64)
			if e != nil {
				return nil, e
			}
		}
		if st.Size() != offset {
			return nil, fmt.Errorf("Rotated EVE contains an incomplete line; cursor retained")
		}
		if time.Since(st.ModTime()) < 2*time.Second {
			return rows, nil
		}
		oldPath := f.Path + "." + strconv.Itoa(rank)
		check, e := os.Stat(oldPath)
		if e != nil || !os.SameFile(st, check) {
			return rows, nil
		}
		rank--
		path := f.Path
		if rank > 0 {
			path += "." + strconv.Itoa(rank)
		}
		info, e := os.Lstat(path)
		if os.IsNotExist(e) {
			return rows, nil
		}
		if e != nil {
			return nil, e
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("EVE successor is not a regular file")
		}
		next, e := os.Open(path)
		if e != nil {
			return nil, e
		}
		nextID, e := lineFileID(next)
		if e != nil {
			next.Close()
			return nil, e
		}
		if nextID == id {
			next.Close()
			return nil, fmt.Errorf("EVE generations share file identity")
		}
		check, e = os.Stat(oldPath)
		if e != nil || !os.SameFile(st, check) {
			next.Close()
			return rows, nil
		}
		file.Close()
		file = next
		saved.Line = ""
	}
	return nil, fmt.Errorf("EVE rotation limit; cursor retained")
}
