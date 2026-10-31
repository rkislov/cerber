// SPDX-License-Identifier: Apache-2.0
package suricatacapture

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
	"strings"
	"syscall"
	"time"
)

type Runtime struct {
	Config
	RulesDirectory string `json:"rules_directory"`
	YAML           string `json:"yaml"`
	Template       string `json:"template"`
}

func LoadRuntime(path string) (Runtime, error) {
	var c Runtime
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	if len(b) > 8192 {
		return c, fmt.Errorf("capture config too large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	if d.Decode(new(any)) != io.EOF {
		return c, fmt.Errorf("trailing capture config")
	}
	return c, c.Validate()
}
func (c Runtime) Validate() error {
	if e := c.Config.Validate(); e != nil {
		return e
	}
	for _, p := range []string{c.RulesDirectory, c.YAML, c.Template} {
		if !filepath.IsAbs(p) || strings.ContainsAny(p, "\n\r\x00") {
			return fmt.Errorf("capture paths must be absolute")
		}
	}
	if c.YAML == c.Template || c.YAML == c.EVEPath || filepath.Dir(c.EVEPath) == c.RulesDirectory {
		return fmt.Errorf("capture paths must be separate")
	}
	return nil
}

// Render starts with the distribution's Suricata 7/8 template, replacing whole
// top-level sections. Generated capture is passive: no NFQUEUE or copy-mode.
func (c Runtime) Render(base string) (string, error) {
	if e := c.Validate(); e != nil {
		return "", e
	}
	if !strings.HasPrefix(base, "%YAML 1.1") {
		return "", fmt.Errorf("expected distribution Suricata YAML template")
	}
	quote := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	sections := map[string]string{
		"default-rule-path": "default-rule-path: " + quote(c.RulesDirectory) + "\n",
		"rule-files":        "rule-files:\n  - " + quote(filepath.Join(c.RulesDirectory, "active.rules")) + "\n",
		"default-log-dir":   "default-log-dir: " + quote(filepath.Dir(c.EVEPath)) + "\n",
		"unix-command":      "unix-command:\n  enabled: yes\n  filename: " + quote(filepath.Join(c.RulesDirectory, "suricata.socket")) + "\n",
		"outputs":           "outputs:\n  - eve-log:\n      enabled: yes\n      filetype: regular\n      filename: " + quote(c.EVEPath) + "\n      filemode: 660\n      community-id: true\n      types:\n        - alert:\n            payload: no\n            packet: no\n            tagged-packets: no\n            metadata:\n              app-layer: false\n              flow: true\n              rule:\n                metadata: false\n                raw: false\n        - flow\n",
		"af-packet":         "af-packet:\n  - interface: " + quote(c.Interface) + "\n    threads: 1\n    cluster-id: 99\n    cluster-type: cluster_flow\n    defrag: yes\n    use-mmap: yes\n    tpacket-v3: yes\n",
		"stats":             "stats:\n  enabled: no\n",
		"logging":           "logging:\n  default-log-level: notice\n  outputs:\n    - console:\n        enabled: yes\n",
	}
	// Each section ends at the next non-indented YAML key. Comments are retained
	// only outside replaced sections; duplicate active keys are rejected.
	keyRE := regexp.MustCompile(`(?m)^[a-zA-Z][a-zA-Z0-9_-]*:`)
	indexes := keyRE.FindAllStringIndex(base, -1)
	var out strings.Builder
	pos := 0
	seen := map[string]bool{}
	for k, m := range indexes {
		key := strings.TrimSuffix(base[m[0]:m[1]], ":")
		replacement, ok := sections[key]
		if !ok {
			continue
		}
		if seen[key] {
			return "", fmt.Errorf("duplicate template section %s", key)
		}
		seen[key] = true
		end := len(base)
		if k+1 < len(indexes) {
			end = indexes[k+1][0]
		}
		out.WriteString(base[pos:m[0]])
		out.WriteString(replacement)
		out.WriteByte('\n')
		pos = end
	}
	out.WriteString(base[pos:])
	for key, value := range sections {
		if !seen[key] {
			out.WriteString("\n" + value)
		}
	}
	result := out.String()
	result = strings.ReplaceAll(result, "  profile: medium", "  profile: low")
	// Force passive IDS even if the local template's stream default changes.
	result = regexp.MustCompile(`(?m)^  inline:.*$`).ReplaceAllString(result, "  inline: no")
	return result, nil
}

func Run(ctx context.Context, c Runtime, log io.Writer) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("SPAN/TAP capture requires Linux")
	}
	if e := c.Validate(); e != nil {
		return e
	}
	if c.Mode == "test" {
		interfaces, e := net.Interfaces()
		if e != nil {
			return e
		}
		for _, i := range interfaces {
			if i.Name != "lo" && i.Name != "cerber-span" && i.Name != "cerber-tap" {
				return fmt.Errorf("test mode requires an isolated network namespace")
			}
		}
		if _, e = net.InterfaceByName("cerber-span"); e != nil {
			if e = exec.CommandContext(ctx, "/usr/sbin/ip", "link", "add", "cerber-span", "type", "veth", "peer", "name", "cerber-tap").Run(); e != nil {
				return e
			}
		}
		for _, name := range []string{"cerber-span", "cerber-tap"} {
			if e = exec.CommandContext(ctx, "/usr/sbin/ip", "link", "set", name, "up").Run(); e != nil {
				return e
			}
		}
	}
	iface, e := net.InterfaceByName(c.Interface)
	if e != nil || iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("capture interface must exist and be up")
	}
	if c.Mode != "test" {
		addrs, e := iface.Addrs()
		if e != nil {
			return e
		}
		if len(addrs) > 0 {
			return fmt.Errorf("SPAN/TAP interface must have no assigned addresses; management interface cannot be used")
		}
	}
	base, e := os.ReadFile(c.Template)
	if e != nil {
		return e
	}
	yaml, e := c.Render(string(base))
	if e != nil {
		return e
	}
	for _, p := range []string{c.RulesDirectory, filepath.Dir(c.EVEPath), filepath.Dir(c.YAML)} {
		if e = os.MkdirAll(p, 0770); e != nil {
			return e
		}
	}
	if e = os.Chmod(filepath.Dir(c.EVEPath), 0770); e != nil {
		return e
	}
	rule := filepath.Join(c.RulesDirectory, "active.rules")
	if _, e = os.Lstat(rule); os.IsNotExist(e) {
		if e = os.WriteFile(rule, []byte("# Assign a signed ruleset from SIEM\n"), 0600); e != nil {
			return e
		}
	}
	temp := c.YAML + ".candidate"
	if e = os.WriteFile(temp, []byte(yaml), 0640); e != nil {
		return e
	}
	defer os.Remove(temp)
	test := exec.CommandContext(ctx, "/usr/bin/suricata", "-T", "--init-errors-fatal", "-c", temp, "--set", "unix-command.enabled=no")
	test.Stdout = log
	test.Stderr = log
	if e = test.Run(); e != nil {
		return fmt.Errorf("capture configuration validation failed: %w", e)
	}
	if e = os.Rename(temp, c.YAML); e != nil {
		return e
	}
	if e = limitFiles(); e != nil {
		return e
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/suricata", "-c", c.YAML, "--af-packet="+c.Interface, "--runmode", "workers")
	cmd.Stdout = log
	cmd.Stderr = log
	cmd.WaitDelay = 15 * time.Second
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	e = cmd.Run()
	if ctx.Err() != nil {
		return nil
	}
	return e
}
