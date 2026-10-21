// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"github.com/rkislov/cerber/internal/patch"
	"io"
	"path/filepath"
)

func patchCommand(ctx context.Context, args []string, out, errOut io.Writer) error {
	f := flags("patch", errOut)
	if len(args) < 1 {
		return patch.ErrInvalid
	}
	switch args[0] {
	case "keygen":
		path := f.String("out", "", "private signing key path (.pub is also written)")
		if e := parse(f, args[1:]); e != nil {
			return e
		}
		if *path == "" {
			return patch.ErrInvalid
		}
		return patch.Generate(*path)
	case "executor":
		path := f.String("config", "", "private executor config path")
		if e := parse(f, args[1:]); e != nil {
			return e
		}
		if !filepath.IsAbs(*path) {
			return fmt.Errorf("absolute executor config required")
		}
		if e := patch.ProtectExecutorConfig(*path); e != nil {
			return e
		}
		var c patch.ExecutorConfig
		if e := patch.ReadJSON(*path, &c); e != nil {
			return e
		}
		return patch.Executor(ctx, c, (patch.Native{}).Execute, func(e error) { fmt.Fprintln(errOut, "patch executor:", e) })
	}
	return patch.ErrInvalid
}
