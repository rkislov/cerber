//go:build windows

// SPDX-License-Identifier: Apache-2.0
//
package eventcollector

// Native managed capture requires Linux; model tests remain portable.
func syncDirectory(string) error { return nil }
