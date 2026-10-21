// SPDX-License-Identifier: Apache-2.0
package eventstore

import "golang.org/x/sys/windows"

func syncArchiveDirectory(string) error { return nil } // Publication uses MOVEFILE_WRITE_THROUGH.
func publishArchive(from, to string) error {
	a, e := windows.UTF16PtrFromString(from)
	if e != nil {
		return e
	}
	b, e := windows.UTF16PtrFromString(to)
	if e != nil {
		return e
	}
	return windows.MoveFileEx(a, b, windows.MOVEFILE_WRITE_THROUGH)
}
