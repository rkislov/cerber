//go:build !linux && !windows

// SPDX-License-Identifier: Apache-2.0
package patch

import "fmt"

func executorLock(string) (func(), error) {
	return nil, fmt.Errorf("patch executor requires Linux or Windows")
}
func protectedPaths(...string) error { return nil }
