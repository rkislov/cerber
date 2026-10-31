//go:build !windows

// SPDX-License-Identifier: Apache-2.0
//
package eventcollector

import "os"

func syncDirectory(path string) error {
	d, e := os.Open(path)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
