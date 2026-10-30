// SPDX-License-Identifier: Apache-2.0
package eventcollector

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
)

func lineFileID(f *os.File) (string, error) {
	var s windows.ByHandleFileInformation
	if e := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &s); e != nil {
		return "", e
	}
	return fmt.Sprintf("%x-%x-%x", s.VolumeSerialNumber, s.FileIndexHigh, s.FileIndexLow), nil
}
