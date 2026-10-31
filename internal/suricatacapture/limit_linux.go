//go:build linux

// SPDX-License-Identifier: Apache-2.0
package suricatacapture

import "golang.org/x/sys/unix"

func limitFiles() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return err
	}
	return unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: uint64(FileLimit), Max: uint64(FileLimit)})
}
