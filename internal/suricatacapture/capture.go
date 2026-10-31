// SPDX-License-Identifier: Apache-2.0
// Package suricatacapture connects a locally selected passive SPAN/TAP interface
// to the separately running Suricata engine. No remote capture commands are accepted.
package suricatacapture

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const RotateBytes int64 = 16 << 20
const FileLimit int64 = 64 << 20

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

type Config struct {
	Interface string `json:"interface"`
	Mode      string `json:"mode"`
	EVEPath   string `json:"eve_path"`
}

func (c Config) Validate() error {
	if !interfaceName.MatchString(c.Interface) || c.Interface == "lo" || c.Mode != "span" && c.Mode != "tap" && c.Mode != "test" || !filepath.IsAbs(c.EVEPath) || filepath.Base(c.EVEPath) != "eve.json" {
		return fmt.Errorf("capture requires an explicit SPAN/TAP interface, mode and absolute eve.json path")
	}
	if c.Mode == "test" && c.Interface != "cerber-span" {
		return fmt.Errorf("test mode requires cerber-span")
	}
	return nil
}

type Status struct {
	Version          int        `json:"version"`
	Mode             string     `json:"mode"`
	Interface        string     `json:"interface"`
	State            string     `json:"state"`
	ObservedAt       time.Time  `json:"observed_at"`
	EngineVersion    string     `json:"engine_version,omitempty"`
	Backend          string     `json:"backend,omitempty"`
	Uptime           uint64     `json:"uptime_seconds"`
	Packets          uint64     `json:"packets"`
	Dropped          uint64     `json:"dropped"`
	InvalidChecksums uint64     `json:"invalid_checksums"`
	EVEBytes         int64      `json:"eve_bytes"`
	EVEState         string     `json:"eve_state"`
	EVEUpdatedAt     *time.Time `json:"eve_updated_at,omitempty"`
	Error            string     `json:"error,omitempty"`
}

func (s Status) Validate() error {
	if s.Version != 1 || !interfaceName.MatchString(s.Interface) || s.Mode != "span" && s.Mode != "tap" && s.Mode != "test" || s.ObservedAt.IsZero() || s.State != "unavailable" && s.State != "waiting" && s.State != "receiving" || s.EVEBytes < 0 || len(s.EngineVersion) > 128 || len(s.Backend) > 64 || len(s.Error) > 256 {
		return fmt.Errorf("invalid capture status")
	}
	switch s.EVEState {
	case "ready", "missing", "rotation_pending", "backlog", "limit", "error":
	default:
		return fmt.Errorf("invalid EVE status")
	}
	return nil
}

type Command func(context.Context, string, map[string]string) (json.RawMessage, error)

func Probe(ctx context.Context, c Config, cmd Command) Status {
	s := Status{Version: 1, Mode: c.Mode, Interface: c.Interface, State: "unavailable", ObservedAt: time.Now().UTC(), EVEState: "ready"}
	for _, p := range []string{c.EVEPath, c.EVEPath + ".1"} {
		st, e := os.Lstat(p)
		if os.IsNotExist(e) {
			if p == c.EVEPath {
				s.EVEState = "missing"
			}
			continue
		}
		if e != nil || !st.Mode().IsRegular() {
			s.EVEState = "error"
			continue
		}
		s.EVEBytes += st.Size()
		if p == c.EVEPath {
			at := st.ModTime().UTC()
			s.EVEUpdatedAt = &at
			if st.Size() >= FileLimit {
				s.EVEState = "limit"
			} else if st.Size() >= RotateBytes {
				s.EVEState = "backlog"
			}
		}
	}
	if _, e := os.Lstat(c.EVEPath + ".rotate-pending"); e == nil {
		s.EVEState = "rotation_pending"
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	fail := func() Status {
		s.Error = "Движок или интерфейс захвата недоступен"
		return s
	}
	for name, target := range map[string]any{"version": &s.EngineVersion, "capture-mode": &s.Backend, "uptime": &s.Uptime} {
		b, e := cmd(ctx, name, nil)
		if e != nil || json.Unmarshal(b, target) != nil {
			return fail()
		}
	}
	var list struct {
		Interfaces []string `json:"ifaces"`
	}
	b, e := cmd(ctx, "iface-list", nil)
	if e != nil || json.Unmarshal(b, &list) != nil {
		return fail()
	}
	found := false
	for _, i := range list.Interfaces {
		found = found || i == c.Interface
	}
	if !found {
		return fail()
	}
	var stats struct {
		Packets uint64 `json:"pkts"`
		Dropped uint64 `json:"drop"`
		Invalid uint64 `json:"invalid-checksums"`
	}
	b, e = cmd(ctx, "iface-stat", map[string]string{"iface": c.Interface})
	if e != nil || json.Unmarshal(b, &stats) != nil {
		return fail()
	}
	s.Packets, s.Dropped, s.InvalidChecksums = stats.Packets, stats.Dropped, stats.Invalid
	s.State = "waiting"
	if s.Packets > 0 {
		s.State = "receiving"
	}
	return s
}
