// SPDX-License-Identifier: Apache-2.0
package eventcollector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRotatingEVEGenerationsReplayRestartAndMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	write := func(p, s string) {
		t.Helper()
		if e := os.WriteFile(p, []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
		at := time.Now().Add(-time.Minute)
		os.Chtimes(p, at, at)
	}
	source := func() RotatingLineFile {
		return RotatingLineFile{LineFile{Path: path, Source: "network:suricata", Identity: "eve", Encode: func(s string) ([]byte, error) { return json.Marshal(s) }}}
	}
	write(path, "first\n")
	r, e := source().Read(context.Background(), "")
	if e != nil || len(r) != 1 {
		t.Fatal(r, e)
	}
	cursor := r[0].Cursor
	os.Rename(path, path+".1")
	write(path, "second\n")
	os.Rename(path+".1", path+".2")
	os.Rename(path, path+".1")
	write(path, "third\n")
	r, e = source().Read(context.Background(), cursor)
	if e != nil || len(r) != 1 || string(r[0].Data) != `"second"` {
		t.Fatal(r, e)
	}
	replay, e := source().Read(context.Background(), cursor)
	if e != nil || replay[0].ID != r[0].ID {
		t.Fatal("unstable replay", e)
	}
	r, e = source().Read(context.Background(), r[0].Cursor)
	if e != nil || len(r) != 1 || string(r[0].Data) != `"third"` {
		t.Fatal(r, e)
	}
	cursor = r[0].Cursor
	write(path, "x\n")
	if _, e = source().Read(context.Background(), cursor); e == nil {
		t.Fatal("copytruncate accepted")
	}
	os.Remove(path)
	if _, e = source().Read(context.Background(), cursor); e == nil {
		t.Fatal("missing generation ignored")
	}
}
func TestRotatingEVEPartialAndLegacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	os.WriteFile(path, []byte("first\npartial"), 0600)
	line := LineFile{Path: path, Source: "network:suricata", Identity: "eve", Encode: func(s string) ([]byte, error) { return json.Marshal(s) }}
	r, e := line.Read(context.Background(), "")
	if e != nil {
		t.Fatal(e)
	}
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString(" end\n")
	f.Close()
	r, e = (RotatingLineFile{line}).Read(context.Background(), r[0].Cursor)
	if e != nil || len(r) != 1 {
		t.Fatal(r, e)
	}
	cursor := r[0].Cursor
	f, _ = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString("unfinished")
	f.Close()
	os.Rename(path, path+".1")
	os.WriteFile(path, []byte("new\n"), 0600)
	if _, e = (RotatingLineFile{line}).Read(context.Background(), cursor); e == nil {
		t.Fatal("partial rotated line skipped")
	}
}
