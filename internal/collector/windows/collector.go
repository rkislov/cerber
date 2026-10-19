// SPDX-License-Identifier: Apache-2.0
package windows

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
	"unicode/utf16"

	"github.com/rkislov/cerber/internal/inventory"
)

//go:embed inventory.ps1
var script string

type Collector struct {
	CheckAvailable bool
	Timeout        time.Duration
	// Runner permits a remote/transport adapter or deterministic tests without changing the script.
	Runner func(context.Context, string) ([]byte, error)
}

func (c Collector) Collect(ctx context.Context) (inventory.Snapshot, error) {
	var result inventory.Snapshot
	runner := c.Runner
	if runner == nil {
		if runtime.GOOS != "windows" {
			return result, fmt.Errorf("local Windows inventory requires Windows; use JSON import for collected remote data")
		}
		runner = runPowerShell
	}
	limit := c.Timeout
	if limit <= 0 {
		limit = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	enabled := "$false"
	if c.CheckAvailable {
		enabled = "$true"
	}
	data, err := runner(ctx, "$CheckAvailable = "+enabled+"\n"+script)
	if err != nil {
		return result, err
	}
	if int64(len(data)) > inventory.MaxSnapshotBytes {
		return result, fmt.Errorf("inventory exceeds 32 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&result); err != nil {
		return result, fmt.Errorf("decode Windows inventory: %w", err)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return result, fmt.Errorf("trailing Windows collector output")
	}
	if err = result.Validate(); err != nil {
		return result, err
	}
	return result, nil
}

type limitedBuffer struct {
	bytes.Buffer
	limit int64
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if int64(b.Len()+len(p)) > b.limit {
		return 0, fmt.Errorf("collector output limit exceeded")
	}
	return b.Buffer.Write(p)
}
func runPowerShell(ctx context.Context, source string) ([]byte, error) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		return nil, fmt.Errorf("SystemRoot is missing")
	}
	encoded := utf16.Encode([]rune(source))
	raw := make([]byte, len(encoded)*2)
	for i, v := range encoded {
		binary.LittleEndian.PutUint16(raw[i*2:], v)
	}
	cmd := exec.CommandContext(ctx, filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw))
	out := &limitedBuffer{limit: inventory.MaxSnapshotBytes}
	errOut := &limitedBuffer{limit: 64 << 10}
	cmd.Stdout = out
	cmd.Stderr = errOut
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("Windows collector failed: %w: %s", err, errOut.String())
	}
	return out.Bytes(), nil
}
