// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"github.com/rkislov/cerber/internal/eventcollector"
	"github.com/rkislov/cerber/internal/telemetry"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func separateEventDatabase(path, control string) error {
	if path == ":memory:" || strings.HasPrefix(path, "file:") {
		return fmt.Errorf("events-db must be a separate durable filesystem path")
	}
	absolute, e := filepath.Abs(path)
	if e != nil {
		return e
	}
	other, e := filepath.Abs(control)
	if e != nil {
		return e
	}
	if absolute == other {
		return fmt.Errorf("event and control databases must be separate")
	}
	a, ae := os.Stat(absolute)
	b, be := os.Stat(other)
	if ae == nil && be == nil && os.SameFile(a, b) {
		return fmt.Errorf("event and control databases must be separate")
	}
	return nil
}
func parseEventSources(value string) ([]eventcollector.Source, error) {
	out := []eventcollector.Source{}
	if value == "" {
		return out, nil
	}
	seen := map[string]bool{}
	for _, s := range strings.Split(value, ",") {
		if !telemetry.ValidSource(s) || seen[s] {
			return nil, fmt.Errorf("invalid or duplicate event source")
		}
		if s == "journald" && runtime.GOOS != "linux" || s != "journald" && runtime.GOOS != "windows" {
			return nil, fmt.Errorf("event source requires target OS")
		}
		seen[s] = true
		out = append(out, eventcollector.Native{Source: s})
	}
	return out, nil
}
