// SPDX-License-Identifier: Apache-2.0
package eventcollector

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReceiverPersistsCompleteFramesAndCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := filepath.Join(t.TempDir(), "cef")
	f, e := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() { done <- serveCEF(ctx, l, f, func(error) {}) }()
	c, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.Write([]byte("CEF:first\nCEF:second\n"))
	deadline := time.Now().Add(time.Second)
	for {
		b, _ := os.ReadFile(p)
		if string(b) == "CEF:first\nCEF:second\n" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not persisted", string(b))
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown blocked")
	}
}
func TestReceiverRejectsPublicListener(t *testing.T) {
	if e := ReceiveCEF(context.Background(), "0.0.0.0:5514", filepath.Join(t.TempDir(), "cef"), func(error) {}); e == nil {
		t.Fatal("public syslog accepted")
	}
}
