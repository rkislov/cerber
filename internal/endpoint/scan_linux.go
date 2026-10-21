//go:build linux

// SPDX-License-Identifier: Apache-2.0
package endpoint

import (
	"os"
	"strings"
)

func scanRoots() []string { return []string{"/"} }
func scanExclusions() []string {
	out := []string{"/proc", "/sys", "/dev", "/run"}
	b, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil {
		return append(out, "/")
	}
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.Split(line, " - ")
		if len(parts) != 2 {
			continue
		}
		left, right := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(left) < 5 || len(right) < 1 || left[4] == "/" {
			continue
		}
		switch right[0] {
		case "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "ntfs", "ntfs3", "vfat", "exfat", "tmpfs":
		default:
			out = append(out, strings.ReplaceAll(left[4], `\040`, " "))
		}
	}
	return out
}
