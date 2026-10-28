//go:build !linux && !darwin && !windows

// SPDX-License-Identifier: Apache-2.0
package health

import "fmt"

func DiskSpace(string) (uint64, uint64, string, error) {
	return 0, 0, "", fmt.Errorf("disk capacity probe unavailable on this platform")
}
