// SPDX-License-Identifier: Apache-2.0
//go:build !windows

package main

import "fmt"

func runService(args []string) (bool, error) {
	if len(args) >= 2 && args[0] == "agent" && args[1] == "service-run" {
		return true, fmt.Errorf("service-run is Windows SCM only; use agent run -config with systemd")
	}
	return false, nil
}
