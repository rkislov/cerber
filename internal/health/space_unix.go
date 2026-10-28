//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package health

import (
	"fmt"
	"syscall"
)

// DiskSpace reports space available to the service account, excluding reserved blocks.
func DiskSpace(path string) (available, total uint64, identity string, err error) {
	var s syscall.Statfs_t
	err = syscall.Statfs(path, &s)
	if err == nil {
		available = s.Bavail * uint64(s.Bsize)
		total = s.Blocks * uint64(s.Bsize)
		identity = fmt.Sprint(s.Fsid)
	}
	return
}
