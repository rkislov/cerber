//go:build windows

// SPDX-License-Identifier: Apache-2.0
package endpoint

import (
	"fmt"
	"golang.org/x/sys/windows"
)

func scanRoots() []string {
	out := []string{}
	for c := 'A'; c <= 'Z'; c++ {
		p := fmt.Sprintf("%c:\\", c)
		ptr, e := windows.UTF16PtrFromString(p)
		if e == nil && windows.GetDriveType(ptr) == windows.DRIVE_FIXED {
			out = append(out, p)
		}
	}
	return out
}
func scanExclusions() []string { return []string{} }
