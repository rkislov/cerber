// SPDX-License-Identifier: Apache-2.0
package netsensor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rkislov/cerber/internal/eventcollector"
	"github.com/rkislov/cerber/internal/eventstore"
	"github.com/rkislov/cerber/internal/telemetry"
)

func TestEVEWakeAfterWriteThroughRotatedDescriptor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	writer, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	wake, stop := eveWakeups(t.Context(), path)
	defer stop()
	wait := func() {
		t.Helper()
		select {
		case <-wake:
		case <-time.After(3 * time.Second):
			t.Fatal("no EVE wakeup")
		}
	}
	wait() // Watch attached, all prior filesystem operations completed.
	if err := os.WriteFile(filepath.Join(dir, "suricata.log"), []byte("unrelated"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-wake:
		t.Fatal("unrelated log woke the EVE reader")
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := writer.WriteString("late line\n"); err != nil {
		t.Fatal(err)
	}
	wait()
}

func TestEVEWritesDoNotShortenSpoolBackoff(t *testing.T) {
	dir := t.TempDir()
	input := Input{ID: "eve", Format: "suricata", Protocol: "file", Path: filepath.Join(dir, "eve.json")}
	writer, err := os.Create(input.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	queue, err := eventstore.Open(t.Context(), filepath.Join(dir, "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	r := newReceiver(blockedFileQueue{queue}, "agent")
	if err := r.configure(Config{Inputs: []Input{input}, Spool: filepath.Join(dir, "queue.db")}); err != nil {
		t.Fatal(err)
	}
	source := eventcollector.RotatingLineFile{LineFile: eventcollector.LineFile{
		Path: input.Path, Source: input.Source(), Identity: input.ID,
		Encode: func(line string) ([]byte, error) { return json.Marshal(line) },
	}}
	if _, err := writer.WriteString("first\n"); err != nil {
		t.Fatal(err)
	}
	worker, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	attempt := make(chan time.Time, 2)
	go func() {
		defer close(done)
		(meteredFile{input: input, source: source}).collect(worker, r, make(chan struct{}, 1), func(err error) {
			if err != telemetry.ErrFull {
				t.Errorf("unexpected source error: %v", err)
			}
			select {
			case attempt <- time.Now():
			case <-worker.Done():
			}
		})
	}()
	defer func() { cancel(); <-done }()
	nextAttempt := func() time.Time {
		t.Helper()
		select {
		case at := <-attempt:
			return at
		case <-time.After(4 * time.Second):
			t.Fatal("missing retry")
			return time.Time{}
		}
	}
	first := nextAttempt()
	for i := 0; i < 50; i++ {
		if _, err := writer.WriteString("more\n"); err != nil {
			t.Fatal(err)
		}
	}
	if delay := nextAttempt().Sub(first); delay < time.Second {
		t.Fatalf("write notifications bypassed full-spool backoff: %v", delay)
	}
	if cursor, err := queue.SourceCursor(t.Context(), r.agent, input.Source()); err != nil || cursor != "" {
		t.Fatalf("cursor changed on failed enqueue: %q, %v", cursor, err)
	}
}
