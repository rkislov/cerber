//go:build !windows

// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"os"
	"path/filepath"
)

func syncArchiveDirectory(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func publishArchive(from, to string) error {
	if e := os.Rename(from, to); e != nil {
		return e
	}
	return syncArchiveDirectory(filepath.Dir(to))
}
