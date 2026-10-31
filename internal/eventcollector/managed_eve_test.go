// SPDX-License-Identifier: Apache-2.0
package eventcollector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManagedEVERotationRecoveryAndBacklog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	ctx := context.Background()
	os.WriteFile(path, []byte("first\n"), 0600)
	fail := true
	reopens := 0
	source := ManagedEVE{RotatingLineFile: RotatingLineFile{LineFile{Path: path, Source: "network:suricata", Identity: "eve", Encode: func(s string) ([]byte, error) { return json.Marshal(s) }}}, RotateBytes: 5, Reopen: func(context.Context) error {
		reopens++
		if fail {
			return fmt.Errorf("engine unavailable")
		}
		if _, e := os.Stat(path); os.IsNotExist(e) {
			return os.WriteFile(path, []byte("second\n"), 0600)
		}
		return nil
	}}
	r, e := source.Read(ctx, "")
	if e != nil || len(r) != 1 {
		t.Fatal(r, e)
	}
	cursor := r[0].Cursor
	if _, e = source.Read(ctx, cursor); e == nil {
		t.Fatal("failed reopen was hidden")
	}
	if _, e = os.Stat(path + ".rotate-pending"); e != nil {
		t.Fatal("missing journal")
	}
	fail = false
	old := time.Now().Add(-time.Minute)
	os.Chtimes(path+".1", old, old)
	r, e = source.Read(ctx, cursor)
	if e != nil || len(r) != 1 || string(r[0].Data) != `"second"` {
		t.Fatal(r, e)
	}
	// Cursor not committed: replay must retain the unread successor, even oversized.
	replay, e := source.Read(ctx, cursor)
	if e != nil || len(replay) != 1 || replay[0].ID != r[0].ID {
		t.Fatal("backlog lost", replay, e)
	}
	current := r[0].Cursor
	r, e = source.Read(ctx, current)
	if e != nil {
		t.Fatal(e)
	}
	os.Chtimes(path+".1", old, old)
	if _, e = os.Stat(path + ".1"); e != nil {
		t.Fatal(e)
	}
	if reopens != 3 {
		t.Fatal(reopens)
	}
}
func TestManagedEVECrashBeforeRenameCompletesIntent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	os.WriteFile(path, []byte("saved\n"), 0600)
	id, _, _ := regularID(path)
	os.WriteFile(path+".rotate-pending", []byte(id), 0600)
	line := RotatingLineFile{LineFile{Path: path, Source: "network:suricata", Identity: "eve", Encode: func(s string) ([]byte, error) { return json.Marshal(s) }}}
	rows, _ := line.Read(context.Background(), "")
	source := ManagedEVE{RotatingLineFile: line, RotateBytes: 5, Reopen: func(context.Context) error { return os.WriteFile(path, []byte("new\n"), 0600) }}
	_, e := source.Read(context.Background(), rows[0].Cursor)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(path + ".rotate-pending"); !os.IsNotExist(e) {
		t.Fatal("intent not cleared")
	}
	old, _, _ := regularID(path + ".1")
	if old != id {
		t.Fatal("old generation lost")
	}
}
