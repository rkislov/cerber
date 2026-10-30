// SPDX-License-Identifier: Apache-2.0
//go:build !windows

package suricatarules

import "os"

func syncDirectory(path string) error {
	d, e := os.Open(path)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
