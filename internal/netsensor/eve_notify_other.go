//go:build !linux

// SPDX-License-Identifier: Apache-2.0
package netsensor

import "context"

func eveWakeups(context.Context, string) (<-chan struct{}, func()) { return nil, func() {} }
