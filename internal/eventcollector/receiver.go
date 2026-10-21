// SPDX-License-Identifier: Apache-2.0
package eventcollector

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ReceiveCEF is intentionally local-only. Remote sources must terminate authenticated
// TLS at a trusted relay. Legacy syslog TCP has no durable application acknowledgement.
func ReceiveCEF(ctx context.Context, address, path string, onError func(error)) error {
	host, _, e := net.SplitHostPort(address)
	if e != nil {
		return e
	}
	ip, e := netip.ParseAddr(host)
	if e != nil || !ip.IsLoopback() {
		return fmt.Errorf("CEF receiver requires explicit loopback IP")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("CEF spool requires absolute path")
	}
	if st, e := os.Lstat(path); e == nil && !st.Mode().IsRegular() {
		return fmt.Errorf("CEF spool must be a regular file")
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("CEF spool must be a regular file")
	}
	listener, e := net.Listen("tcp", address)
	if e != nil {
		return e
	}
	defer listener.Close()
	return serveCEF(ctx, listener, f, onError)
}
func serveCEF(ctx context.Context, listener net.Listener, f *os.File, onError func(error)) error {
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, 8)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-done:
		}
	}()
	defer func() { close(done); wg.Wait() }()
	for {
		conn, e := listener.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			defer conn.Close()
			connectionDone := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					conn.Close()
				case <-connectionDone:
				}
			}()
			defer close(connectionDone)
			scanner := bufio.NewScanner(conn)
			scanner.Buffer(make([]byte, 16384), 16384)
			for {
				conn.SetReadDeadline(time.Now().Add(30 * time.Second))
				if !scanner.Scan() {
					break
				}
				line := strings.TrimSuffix(scanner.Text(), "\r")
				if len(line) > 15000 || strings.ContainsRune(line, 0) {
					onError(fmt.Errorf("CEF frame rejected"))
					return
				}
				mu.Lock()
				st, e := f.Stat()
				if e == nil && st.Size()+int64(len(line)+1) > 1<<30 {
					e = fmt.Errorf("CEF spool full; operator handover required")
				}
				if e == nil {
					_, e = f.WriteString(line + "\n")
				}
				if e == nil {
					e = f.Sync()
				}
				mu.Unlock()
				if e != nil {
					onError(e)
					return
				}
			}
			if e := scanner.Err(); e != nil && ctx.Err() == nil {
				onError(fmt.Errorf("CEF stream ended with read error"))
			}
		}()
	}
}
