// SPDX-License-Identifier: Apache-2.0
//go:build windows

package suricatarules

// Windows does not support flushing a directory handle. The shared lifecycle
// model remains testable here; NativeEngine rejects Windows before activation
// because Suricata's Unix control interface is unavailable there.
func syncDirectory(string) error { return nil }
