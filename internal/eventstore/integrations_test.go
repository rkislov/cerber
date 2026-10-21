// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"github.com/rkislov/cerber/internal/integrations"
	"github.com/rkislov/cerber/internal/telemetry"
	"path/filepath"
	"testing"
	"time"
)

func TestIOCCorrelationReplayAndRestart(t *testing.T) {
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "events.db")
	s, e := Open(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	b := batch(t, "agent", 0, "failure")
	if _, e = s.Accept(ctx, "agent", "asset", b); e != nil {
		t.Fatal(e)
	}
	if e = s.Step(ctx); e != nil {
		t.Fatal(e)
	}
	index := integrations.NewIndex([]integrations.IOC{{ID: "fixture-ioc", Value: "10.1.2.3", Type: "ip", First: time.Now().Add(-24 * time.Hour), Last: time.Now()}})
	for _, revision := range []string{"first-full", "first-full", "next-full"} {
		if e = s.ScanIOC(ctx, index, revision); e != nil {
			t.Fatal(e)
		}
	}
	s.Close()
	s, e = Open(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.ScanIOC(ctx, index, "next-full"); e != nil {
		t.Fatal(e)
	}
	d, e := s.ReadDetections(ctx, 0, 100)
	if e != nil || len(d) != 1 || d[0].Rule != "threatfox.ioc_match" || len(d[0].Evidence) != 1 || d[0].Evidence[0] != telemetry.ID("agent", b.Records[0].ID) {
		t.Fatal(d, e)
	}
	mail, e := s.NotificationBatch(ctx, 0)
	if e != nil || len(mail) != 1 {
		t.Fatal(mail, e)
	}
}
