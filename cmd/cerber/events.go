// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"github.com/rkislov/cerber/internal/agent"
	"github.com/rkislov/cerber/internal/eventcollector"
	"github.com/rkislov/cerber/internal/eventstore"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/telemetry"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
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
		if strings.HasPrefix(s, "cef-fess:") || strings.HasPrefix(s, "cef-firewall:") {
			profile, path, _ := strings.Cut(strings.TrimPrefix(s, "cef-"), ":")
			if !filepath.IsAbs(path) || seen["network:cef"] {
				return nil, fmt.Errorf("CEF requires one absolute append-only spool path")
			}
			seen["network:cef"] = true
			out = append(out, eventcollector.CEFFile{Path: path, Profile: profile})
			continue
		}
		if telemetry.SensorSource(s) {
			return nil, fmt.Errorf("network source requires the separate cerber-sensor component")
		}
		if s == "network:cef" {
			return nil, fmt.Errorf("CEF requires cef-fess:PATH or cef-firewall:PATH")
		}

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

func receiveCEF(ctx context.Context, args []string, errOut io.Writer) error {
	f := flags("events receive-cef", errOut)
	listen := f.String("listen", "127.0.0.1:5514", "local TCP CEF listener")
	path := f.String("file", "", "absolute append-only spool file")
	if err := parse(f, args); err != nil {
		return err
	}
	return eventcollector.ReceiveCEF(ctx, *listen, *path, func(err error) { fmt.Fprintf(errOut, "CEF receiver: %v\n", err) })
}

func forwardCEF(ctx context.Context, args []string, errOut io.Writer) error {
	f := flags("events forward-cef", errOut)
	path := f.String("file", "", "absolute append-only CEF spool")
	profile := f.String("profile", "fess", "fess or firewall")
	database := f.String("spool", "", "absolute durable delivery database")
	credentials := f.String("credentials", "", "private enrolled agent credentials")
	server := f.String("server", "", "HTTPS SIEM origin")
	caFile := f.String("ca-cert", "", "optional trusted CA PEM")
	if err := parse(f, args); err != nil {
		return err
	}
	if !filepath.IsAbs(*path) || !filepath.IsAbs(*database) || *path == *database || (*profile != "fess" && *profile != "firewall") {
		return fmt.Errorf("separate absolute spool paths and explicit profile required")
	}
	c, err := agent.LoadCredentials(*credentials)
	if err != nil {
		return err
	}
	var ca []byte
	if *caFile != "" {
		ca, err = os.ReadFile(*caFile)
		if err != nil {
			return err
		}
	}
	client, err := ingest.NewClient(*server, c, ca)
	if err != nil {
		return err
	}
	spool, err := eventstore.Open(ctx, *database)
	if err != nil {
		return err
	}
	defer spool.Close()
	onError := func(err error) {
		if ctx.Err() == nil {
			fmt.Fprintf(errOut, "CEF forwarder: %v\n", err)
		}
	}
	nextHeartbeat := time.Time{}
	for {
		health := eventcollector.Cycle(ctx, spool, client, c.AgentID, []eventcollector.Source{eventcollector.CEFFile{Path: *path, Profile: *profile}}, onError)
		if !time.Now().Before(nextHeartbeat) {
			_, err = client.Heartbeat(ctx, ingest.Heartbeat{SchemaVersion: 1, AgentID: c.AgentID, ObservedAt: time.Now().UTC(), Platform: runtime.GOOS, Architecture: runtime.GOARCH, CollectionStatus: "not_attempted", DeliveryStatus: "not_attempted", Events: &health})
			if err != nil {
				onError(err)
			}
			nextHeartbeat = time.Now().Add(time.Minute)
		}
		timer := time.NewTimer(10 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
