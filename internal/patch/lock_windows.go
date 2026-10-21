// SPDX-License-Identifier: Apache-2.0
package patch

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

func executorLock(path string) (func(), error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if e != nil {
		return nil, e
	}
	return func() { windows.CloseHandle(h) }, nil
}
func protectedPaths(paths ...string) error {
	for _, path := range paths {
		st, e := os.Lstat(path)
		if e != nil {
			return e
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return ErrInvalid
		}
		sd, e := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if e != nil {
			return e
		}
		owner, _, e := sd.Owner()
		if e != nil {
			return e
		}
		trusted := func(s *windows.SID) bool {
			return s.IsWellKnown(windows.WinLocalSystemSid) || s.IsWellKnown(windows.WinBuiltinAdministratorsSid)
		}
		if !trusted(owner) {
			return fmt.Errorf("executor path owner must be SYSTEM or Administrators: %s", path)
		}
		acl, _, e := sd.DACL()
		if e != nil || acl == nil {
			return fmt.Errorf("executor path requires a restrictive DACL: %s", path)
		}
		for i := uint32(0); i < uint32(acl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if e = windows.GetAce(acl, i, &ace); e != nil {
				return e
			}
			if ace.Header.AceFlags&0x08 != 0 {
				continue
			}
			if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
				continue
			}
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
				return fmt.Errorf("unsupported executor ACL entry: %s", path)
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			const writeMask = windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE | 0x2 | 0x4 | 0x10 | 0x40 | 0x100
			if ace.Mask&writeMask != 0 && !trusted(sid) {
				return fmt.Errorf("executor path is writable by a non-administrator: %s", path)
			}
		}
	}
	return nil
}
