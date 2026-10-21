// SPDX-License-Identifier: Apache-2.0
package eventcollector

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rkislov/cerber/internal/telemetry"
)

// CEFFile tails an append-only, locally protected CEF spool. It never advances
// past an incomplete line. Rotation/truncation requires an operator handover.
type CEFFile struct{ Path, Profile string }

func (f CEFFile) Name() string { return "network:cef" }
func (f CEFFile) Read(ctx context.Context, cursor string) ([]telemetry.Raw, error) {
	if f.Profile != "fess" && f.Profile != "firewall" {
		return nil, telemetry.ErrInvalid
	}
	file, e := os.Open(f.Path)
	if e != nil {
		return nil, e
	}
	defer file.Close()
	st, e := file.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("CEF source must be a regular append-only file")
	}
	var offset int64
	var prefixLen int
	fingerprint := ""
	if cursor != "" {
		p := strings.Split(cursor, ":")
		if len(p) != 3 {
			return nil, telemetry.ErrInvalid
		}
		offset, e = strconv.ParseInt(p[0], 10, 64)
		if e != nil || offset < 1 {
			return nil, telemetry.ErrInvalid
		}
		prefixLen, e = strconv.Atoi(p[1])
		if e != nil || prefixLen < 1 || prefixLen > 1024 || int64(prefixLen) > offset {
			return nil, telemetry.ErrInvalid
		}
		fingerprint = p[2]
		prefix := make([]byte, prefixLen)
		if _, e = file.ReadAt(prefix, 0); e != nil {
			return nil, fmt.Errorf("CEF spool truncated; cursor retained")
		}
		sum := sha256.Sum256(prefix)
		if hex.EncodeToString(sum[:]) != fingerprint {
			return nil, fmt.Errorf("CEF spool replaced; cursor retained")
		}
	}
	if st.Size() < offset {
		return nil, fmt.Errorf("CEF spool truncated; cursor retained")
	}
	if _, e = file.Seek(offset, io.SeekStart); e != nil {
		return nil, e
	}
	reader := bufio.NewReaderSize(io.LimitReader(file, telemetry.MaxBatchBytes), 16385)
	result := []telemetry.Raw{}
	for len(result) < 100 {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		line, e := reader.ReadSlice('\n')
		if e == bufio.ErrBufferFull {
			return nil, fmt.Errorf("CEF line exceeds 16 KiB; cursor retained")
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		offset += int64(len(line))
		text := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
		if len(text) > 15000 {
			return nil, fmt.Errorf("CEF line exceeds payload limit; cursor retained")
		}
		if prefixLen == 0 {
			prefixLen = int(offset)
			if prefixLen > 1024 {
				prefixLen = 1024
			}
			prefix := make([]byte, prefixLen)
			if _, e = file.ReadAt(prefix, 0); e != nil {
				return nil, e
			}
			sum := sha256.Sum256(prefix)
			fingerprint = hex.EncodeToString(sum[:])
		}
		next := fmt.Sprintf("%d:%d:%s", offset, prefixLen, fingerprint)
		data, _ := json.Marshal(map[string]string{"line": text, "profile": f.Profile})
		result = append(result, telemetry.Raw{ID: telemetry.ID(f.Path, f.Profile, next, text), Source: f.Name(), Cursor: next, ObservedAt: time.Now().UTC(), Data: data})
	}
	return result, nil
}
