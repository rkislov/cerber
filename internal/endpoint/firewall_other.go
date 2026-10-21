//go:build !linux && !windows

// SPDX-License-Identifier: Apache-2.0
package endpoint

import "context"

func firewall(context.Context, Block, bool) error { return ErrInvalid }
