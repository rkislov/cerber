// SPDX-License-Identifier: Apache-2.0
package netsensor

import (
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/eventcollector"
	"github.com/rkislov/cerber/internal/telemetry"
	"os"
	"path/filepath"
	"testing"
)

func TestFileMetricsOnlyCountCommittedRecords(t *testing.T) {
	p := filepath.Join(t.TempDir(), "eve.json")
	os.WriteFile(p, []byte("one\ntwo\n"), 0600)
	i := Input{ID: "eve", Format: "suricata", Protocol: "file", Path: p}
	r := newReceiver(nil, "agent")
	r.configure(Config{Inputs: []Input{i}, Spool: filepath.Join(t.TempDir(), "queue.db")})
	f := &meteredFile{input: i, Source: eventcollector.RotatingLineFile{LineFile: eventcollector.LineFile{Path: p, Source: i.Source(), Identity: i.ID, Encode: func(s string) ([]byte, error) { return json.Marshal(s) }}}}
	rows, e := f.Read(context.Background(), "")
	if e != nil || len(rows) != 2 {
		t.Fatal(rows, e)
	}
	f.commitMetrics(r, []telemetry.SourceHealth{{Source: i.Source(), State: "blocked"}})
	s := r.snapshot([]Input{i})
	if s.Inputs[0].Counters.Stored != 0 || s.Inputs[0].LastMessageAt != nil {
		t.Fatal("uncommitted read counted", s)
	}
	rows, e = f.Read(context.Background(), "")
	if e != nil {
		t.Fatal(e)
	}
	f.commitMetrics(r, []telemetry.SourceHealth{{Source: i.Source(), State: "ok"}})
	s = r.snapshot([]Input{i})
	if s.Inputs[0].Counters.Stored != 2 || s.Inputs[0].Counters.Messages != 2 || s.Inputs[0].LastMessageAt == nil {
		t.Fatal(s)
	}
	last := *s.Inputs[0].LastMessageAt
	if _, e = f.Read(context.Background(), rows[1].Cursor); e != nil {
		t.Fatal(e)
	}
	f.commitMetrics(r, []telemetry.SourceHealth{{Source: i.Source(), State: "ok"}})
	s = r.snapshot([]Input{i})
	if s.Inputs[0].Counters.Stored != 2 || !s.Inputs[0].LastMessageAt.Equal(last) {
		t.Fatal("empty read counted", s)
	}
}
