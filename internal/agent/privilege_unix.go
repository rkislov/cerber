//go:build !windows

// SPDX-License-Identifier: Apache-2.0
//
package agent

import "os"

func Privilege() string {
	if os.Geteuid() == 0 {
		return "root"
	}
	return "unprivileged"
}
