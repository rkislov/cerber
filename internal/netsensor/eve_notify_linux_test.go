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

func fileWorkerFixture(t *testing.T) (*Receiver, meteredFile, *os.File, *eventstore.Store) {
	t.Helper()
	dir := t.TempDir()
	input := Input{ID: "eve", Format: "suricata", Protocol: "file", Path: filepath.Join(dir, "eve.json")}
	writer, err := os.Create(input.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { writer.Close() })
	queue, err := eventstore.Open(t.Context(), filepath.Join(dir, "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { queue.Close() })
	r := newReceiver(queue, "agent")
	if err := r.configure(Config{Inputs: []Input{input}, Spool: filepath.Join(dir, "queue.db")}); err != nil {
		t.Fatal(err)
	}
	source := eventcollector.RotatingLineFile{LineFile: eventcollector.LineFile{
		Path: input.Path, Source: input.Source(), Identity: input.ID,
		Encode: func(line string) ([]byte, error) { return json.Marshal(line) },
	}}
	return r, meteredFile{input: input, source: source}, writer, queue
}

func TestEVEWritesDoNotShortenSpoolBackoff(t *testing.T) {
	r, file, writer, queue := fileWorkerFixture(t)
	r.spool = blockedFileQueue{queue}
	if _, err := writer.WriteString("first\n"); err != nil {
		t.Fatal(err)
	}
	worker, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	attempt := make(chan time.Time, 2)
	go func() {
		defer close(done)
		file.collect(worker, r, make(chan struct{}, 1), func(err error) {
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
	if cursor, err := queue.SourceCursor(t.Context(), r.agent, file.input.Source()); err != nil || cursor != "" {
		t.Fatalf("cursor changed on failed enqueue: %q, %v", cursor, err)
	}
}

func TestEVEWakeReattachesToReplacedDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "eve.json")
	wake, stop := eveWakeups(t.Context(), path)
	defer stop()
	expectWake := func() {
		t.Helper()
		select {
		case <-wake:
		case <-time.After(4 * time.Second):
			t.Fatal("directory watch was not restored")
		}
	}
	expectWake()
	if err := os.Rename(dir, dir+".old"); err != nil {
		t.Fatal(err)
	}
	expectWake()
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	expectWake() // The new directory is now watched.
	if err := os.WriteFile(path, []byte("new generation\n"), 0600); err != nil {
		t.Fatal(err)
	}
	expectWake()
}

func TestEVEContinuousWritesBatchAndRetainPartialTail(t *testing.T) {
	r, file, writer, queue := fileWorkerFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	queued := make(chan struct{}, 1)
	go func() {
		defer close(done)
		file.collect(ctx, r, queued, func(err error) { t.Errorf("collect: %v", err) })
	}()
	defer func() { cancel(); <-done }()

	// Let the first complete record commit, then reproduce a stream of short
	// appends at a rate which previously generated dozens of tiny batches.
	if _, err := writer.WriteString("first\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-queued:
	case <-time.After(4 * time.Second):
		t.Fatal("first line was not committed")
	}
	for i := 0; i < 50; i++ {
		if _, err := writer.WriteString("more\n"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := writer.WriteString("unfinished"); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(4 * time.Second); ; {
		if size := file.unreadBytes(ctx, r); size != nil && *size == int64(len("unfinished")) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("complete lines not drained, or cursor advanced past partial line")
		}
		time.Sleep(10 * time.Millisecond)
	}
	batches, _, err := queue.EventQueueUsage(ctx, r.agent)
	if err != nil || batches > 4 {
		t.Fatalf("continuous small writes produced %d batches, err=%v", batches, err)
	}
}
