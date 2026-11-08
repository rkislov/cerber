// SPDX-License-Identifier: Apache-2.0
package netsensor

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// The parent watch survives file rotation. Notifications are only hints: the
// collector always reads from the offset committed in the durable spool.
func eveWakeups(parent context.Context, path string) (<-chan struct{}, func()) {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	wake := make(chan struct{}, 1)
	signal := func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			watchEVEDirectory(ctx, filepath.Clean(path), signal)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}()
	return wake, func() { cancel(); <-done }
}

func watchEVEDirectory(ctx context.Context, path string, signal func()) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return
	}
	defer watcher.Close()
	dir := filepath.Dir(path)
	if err := watcher.Add(dir); err != nil {
		return
	}
	signal() // Cover writes between the previous read and installing the watch.
	for {
		select {
		case <-ctx.Done():
			return
		case <-watcher.Errors:
			// An overflow can hide a directory replacement as well as a write.
			signal()
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Name == dir && event.Has(fsnotify.Rename|fsnotify.Remove) {
				signal()
				return
			}
			if event.Has(fsnotify.Create|fsnotify.Write|fsnotify.Rename|fsnotify.Remove) && eveGeneration(path, event.Name) {
				signal()
			}
		}
	}
}

func eveGeneration(path, name string) bool {
	if name == path {
		return true
	}
	suffix, ok := strings.CutPrefix(name, path+".")
	if !ok {
		return false
	}
	number, err := strconv.Atoi(suffix)
	return err == nil && number >= 1 && number <= 32 && suffix == strconv.Itoa(number)
}
