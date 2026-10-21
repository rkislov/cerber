//go:build !linux && !windows

// SPDX-License-Identifier: Apache-2.0
package endpoint

func scanRoots() []string      { return nil }
func scanExclusions() []string { return nil }
