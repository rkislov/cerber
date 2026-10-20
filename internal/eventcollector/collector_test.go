// SPDX-License-Identifier: Apache-2.0
package eventcollector

import (
	"context"
	"errors"
	"github.com/rkislov/cerber/internal/telemetry"
	"strings"
	"testing"
	"time"
)

func TestJournalPageOrderingAndCursor(t *testing.T) {
	ctx := context.Background()
	calls := 0
	n := Native{Source: "journald", Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls++
		if calls == 1 {
			if !strings.Contains(strings.Join(args, " "), "--reverse") {
				t.Fatal(args)
			}
			return []byte("{\"__CURSOR\":\"b\",\"MESSAGE\":\"two\"}\n{\"__CURSOR\":\"a\",\"MESSAGE\":\"one\"}\n"), nil
		}
		if !strings.Contains(strings.Join(args, " "), "--after-cursor=b") {
			t.Fatal(args)
		}
		return []byte("{\"__CURSOR\":\"c\"}\n"), nil
	}}
	page, e := n.Read(ctx, "")
	if e != nil || len(page) != 2 || page[0].Cursor != "a" || page[1].Cursor != "b" {
		t.Fatal(page, e)
	}
	page, e = n.Read(ctx, "b")
	if e != nil || page[0].Cursor != "c" {
		t.Fatal(page, e)
	}
}
func TestWindowsCursorValidationAndFailure(t *testing.T) {
	called := false
	n := Native{Source: "windows:Security", Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		called = true
		return []byte(`{"record_id":"10","event_id":4625,"time":"2026-01-01T00:00:00Z","fields":{}}`), nil
	}}
	page, e := n.Read(context.Background(), "")
	if e != nil || len(page) != 1 || !called {
		t.Fatal(page, e)
	}
	called = false
	if _, e = n.Read(context.Background(), "10|x';Remove-Item"); e == nil || called {
		t.Fatal("unsafe cursor")
	}
	n.Runner = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("denied") }
	if _, e = n.Read(context.Background(), "10|"+time.Now().UTC().Format(time.RFC3339Nano)); e == nil {
		t.Fatal("hidden failure")
	}
	if telemetry.ID("journald", "a") == telemetry.ID("journald", "b") {
		t.Fatal("cursor identity")
	}
}
