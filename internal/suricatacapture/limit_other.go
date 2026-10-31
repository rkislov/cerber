//go:build !linux

// SPDX-License-Identifier: Apache-2.0
package suricatacapture

import "fmt"

func limitFiles() error { return fmt.Errorf("Linux capture required") }
