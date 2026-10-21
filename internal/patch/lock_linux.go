// SPDX-License-Identifier: Apache-2.0
package patch

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

func executorLock(path string) (func(), error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, e
	}
	return func() { f.Close() }, nil
}
func protectedPaths(paths ...string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("executor must run as root, independently of the network agent")
	}
	for _, original := range paths {
		for p := original; ; p = filepath.Dir(p) {
			st, e := os.Lstat(p)
			if e != nil {
				return e
			}
			var sys unix.Stat_t
			if e = unix.Lstat(p, &sys); e != nil {
				return e
			}
			if sys.Uid != 0 {
				return fmt.Errorf("executor path must be owned by root: %s", p)
			}
			if st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
				return fmt.Errorf("executor paths must not be writable by group/others: %s", p)
			}
			if p == filepath.Dir(p) {
				break
			}
		}
	}
	return nil
}
