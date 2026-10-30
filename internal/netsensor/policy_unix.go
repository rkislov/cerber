//go:build !windows

// SPDX-License-Identifier: Apache-2.0
package netsensor

import (
	"os"
	"path/filepath"
)

func publishPolicy(from, to string) error {
	if e := os.Rename(from, to); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(to))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
