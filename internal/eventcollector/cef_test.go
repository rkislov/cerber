// SPDX-License-Identifier: Apache-2.0
package eventcollector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCEFFileCursorPartialAndReplacement(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cef.log")
	os.WriteFile(p, []byte("first\npartial"), 0600)
	s := CEFFile{Path: p, Profile: "fess"}
	r, e := s.Read(context.Background(), "")
	if e != nil || len(r) != 1 {
		t.Fatal(r, e)
	}
	cursor := r[0].Cursor
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString(" completed\n")
	f.Close()
	r, e = s.Read(context.Background(), cursor)
	if e != nil || len(r) != 1 {
		t.Fatal(r, e)
	}
	again, e := s.Read(context.Background(), cursor)
	if e != nil || again[0].ID != r[0].ID {
		t.Fatal("unstable replay", e)
	}
	os.WriteFile(p, []byte("other\nlonger replacement contents\n"), 0600)
	if _, e = s.Read(context.Background(), cursor); e == nil {
		t.Fatal("replacement accepted")
	}
}
