//go:build !windows

// SPDX-License-Identifier: Apache-2.0
package eventcollector

import (
	"fmt"
	"os"
	"syscall"
)

func lineFileID(f *os.File) (string, error) {
	st, e := f.Stat()
	if e != nil {
		return "", e
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() {
		return "", fmt.Errorf("regular file identity required")
	}
	return fmt.Sprintf("%x-%x", uint64(s.Dev), uint64(s.Ino)), nil
}
