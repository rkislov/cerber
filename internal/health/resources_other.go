//go:build !linux

// SPDX-License-Identifier: Apache-2.0
//
package health

func cpuSeconds() (float64, bool) { return 0, false }
func resources(string) Resources  { return Resources{Scope: "unavailable"} }
