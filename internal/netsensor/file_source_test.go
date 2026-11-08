// SPDX-License-Identifier: Apache-2.0
package netsensor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkislov/cerber/internal/eventcollector"
	"github.com/rkislov/cerber/internal/eventstore"
	"github.com/rkislov/cerber/internal/telemetry"
)

type blockedFileQueue struct{ eventcollector.Spool }

func (blockedFileQueue) Enqueue(context.Context, telemetry.Batch, string, string, string) error {
	return telemetry.ErrFull
}

func TestFileLagFollowsDurableCursorAcrossBackpressureAndRotation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	write := func(path, contents string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	input := Input{ID: "eve", Format: "suricata", Protocol: "file", Path: path}
	queue, err := eventstore.Open(ctx, filepath.Join(dir, "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	r := newReceiver(blockedFileQueue{queue}, "agent")
	if err := r.configure(Config{Inputs: []Input{input}, Spool: filepath.Join(dir, "queue.db")}); err != nil {
		t.Fatal(err)
	}
	f := meteredFile{input: input, source: eventcollector.RotatingLineFile{LineFile: eventcollector.LineFile{
		Path: path, Source: input.Source(), Identity: input.ID,
		Encode: func(s string) ([]byte, error) { return json.Marshal(s) },
	}}}
	stored := func() uint64 { return r.snapshot([]Input{input}).Inputs[0].Counters.Stored }
	expectLag := func(n int64) {
		t.Helper()
		if size := f.unreadBytes(ctx, r); size == nil || *size != n {
			t.Fatalf("expected %d unread bytes, got %v", n, size)
		}
	}
	page := func() telemetry.SourceHealth {
		t.Helper()
		state, records, _ := eventcollector.CollectPage(ctx, r.spool, r.agent, f.source)
		f.recordPage(r, state, records)
		return state
	}
	contents := strings.Repeat("one\n", telemetry.MaxRecords+1)
	write(path, contents)
	if state := page(); state.State != "blocked" || stored() != 0 {
		t.Fatal("uncommitted read counted", state)
	}
	expectLag(int64(len(contents)))
	r.spool = queue
	if state := page(); state.State != "ok" || stored() != telemetry.MaxRecords {
		t.Fatal("first committed page", state, stored())
	}
	expectLag(4)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	write(path, "two\npartial")
	expectLag(15)
	if state := page(); state.State != "ok" || stored() != telemetry.MaxRecords+1 {
		t.Fatal("rotated tail", state)
	}
	expectLag(11)
	if err := os.Remove(path + ".1"); err != nil {
		t.Fatal(err)
	}
	if f.unreadBytes(ctx, r) != nil {
		t.Fatal("lost generation reported as caught up")
	}
}
