// SPDX-License-Identifier: Apache-2.0
package suricatarules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Engine paths are locally configured; the server cannot choose executables,
// arguments, capture devices or arbitrary output files.
type Engine interface {
	Major(context.Context) (int, error)
	Test(context.Context, string) error
	Reload(context.Context, int) error
}
type NativeEngine struct{ Config Config }
type cappedOutput struct{ bytes.Buffer }

func (b *cappedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len() < 8192 {
		_, _ = b.Buffer.Write(p[:min(n, 8192-b.Len())])
	}
	return n, nil
}
func (e NativeEngine) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, e.Config.Binary, args...)
	var out cappedOutput
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	return out.Bytes(), err
}

var versionRE = regexp.MustCompile(`(?i)suricata(?: version)?\s+(\d+)\.`)

func (e NativeEngine) Major(ctx context.Context) (int, error) {
	if runtime.GOOS == "windows" {
		return 0, fmt.Errorf("Suricata rule reload requires a Unix control socket; use a Linux sensor")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	b, err := e.run(ctx, "-V")
	if err != nil {
		return 0, fmt.Errorf("Suricata executable unavailable")
	}
	m := versionRE.FindSubmatch(b)
	if m == nil {
		return 0, ErrInvalid
	}
	n, _ := strconv.Atoi(string(m[1]))
	if n != 7 && n != 8 {
		return n, fmt.Errorf("Suricata 7 or 8 required")
	}
	return n, nil
}
func (e NativeEngine) Test(ctx context.Context, rules string) error {
	logs, err := os.MkdirTemp(e.Config.Directory, ".test-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(logs)
	output, err := e.run(ctx, "-T", "--init-errors-fatal", "-c", e.Config.YAML, "-S", rules, "-l", logs, "--set", "unix-command.enabled=no")
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if len(detail) > 350 {
			detail = detail[len(detail)-350:]
		}
		return fmt.Errorf("suricata -T failed (%v): %s", err, detail)
	}
	return nil
}
func (e NativeEngine) socket(ctx context.Context, command string, args map[string]string) (json.RawMessage, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", e.Config.Socket)
	if err != nil {
		return nil, fmt.Errorf("Suricata control socket unavailable")
	}
	defer c.Close()
	deadline := time.Now().Add(2 * time.Minute)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	enc := json.NewEncoder(c)
	dec := json.NewDecoder(io.LimitReader(c, 65536))
	var response struct {
		Return  string          `json:"return"`
		Message json.RawMessage `json:"message"`
	}
	if err = enc.Encode(map[string]string{"version": "0.2"}); err != nil {
		return nil, err
	}
	if err = dec.Decode(&response); err != nil || response.Return != "OK" {
		return nil, fmt.Errorf("Suricata socket handshake failed")
	}
	if err = enc.Encode(map[string]any{"command": command, "arguments": args}); err != nil {
		return nil, err
	}
	if err = dec.Decode(&response); err != nil || response.Return != "OK" {
		return nil, fmt.Errorf("Suricata command %s failed", command)
	}
	return response.Message, nil
}

// CaptureCommand exposes only bounded diagnostics and log reopen to the local
// capture integration. It cannot be used for shutdown or arbitrary mutations.
func (e NativeEngine) CaptureCommand(ctx context.Context, command string, args map[string]string) (json.RawMessage, error) {
	switch command {
	case "version", "uptime", "capture-mode", "iface-list", "iface-stat", "reopen-log-files":
		return e.socket(ctx, command, args)
	}
	return nil, ErrInvalid
}
func (e NativeEngine) Reload(ctx context.Context, count int) error {
	// Check the *running* engine loads precisely the managed absolute rule file.
	b, err := e.socket(ctx, "conf-get", map[string]string{"variable": "rule-files.0"})
	if err != nil {
		return err
	}
	var path string
	if json.Unmarshal(b, &path) != nil || path != filepath.Join(e.Config.Directory, "active.rules") {
		return fmt.Errorf("running Suricata rule-files.0 must point to the managed active.rules")
	}
	// Additional rule files would make count-based confirmation ambiguous.
	if _, err = e.socket(ctx, "conf-get", map[string]string{"variable": "rule-files.1"}); err == nil {
		return fmt.Errorf("running Suricata must use only the managed rule file")
	}
	if _, err = e.socket(ctx, "ruleset-reload-rules", nil); err != nil {
		return err
	}
	b, err = e.socket(ctx, "ruleset-stats", nil)
	if err != nil {
		return err
	}
	var stats []struct {
		Loaded int `json:"rules_loaded"`
		Failed int `json:"rules_failed"`
	}
	if json.Unmarshal(b, &stats) != nil || len(stats) != 1 || stats[0].Failed != 0 || stats[0].Loaded != count {
		return fmt.Errorf("Suricata reload count/failed-rule confirmation mismatch")
	}
	return nil
}
