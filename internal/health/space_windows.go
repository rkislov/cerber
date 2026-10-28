//go:build windows

// SPDX-License-Identifier: Apache-2.0
package health

import (
	"golang.org/x/sys/windows"
	"path/filepath"
	"strings"
)

func DiskSpace(path string) (available, total uint64, identity string, err error) {
	abs, e := filepath.Abs(path)
	if e != nil {
		return 0, 0, "", e
	}
	p, e := windows.UTF16PtrFromString(abs)
	if e != nil {
		return 0, 0, "", e
	}
	var free uint64
	err = windows.GetDiskFreeSpaceEx(p, &available, &total, &free)
	if err != nil {
		return
	}
	root := make([]uint16, 32768)
	err = windows.GetVolumePathName(p, &root[0], uint32(len(root)))
	if err == nil {
		identity = strings.ToLower(windows.UTF16ToString(root))
	}
	return
}
