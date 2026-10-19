// SPDX-License-Identifier: Apache-2.0
package linux

import (
	"bytes"
	"context"
	"fmt"
	"github.com/rkislov/cerber/internal/inventory"
	"os"
	"os/exec"
	"strings"
)

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}
type Runner func(context.Context, string, ...string) (Result, error)
type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, fmt.Errorf("package manager output exceeds limit")
	}
	return b.Buffer.Write(p)
}
func run(ctx context.Context, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	env := []string{}
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "LC_") && !strings.HasPrefix(v, "LANG=") && !strings.HasPrefix(v, "LANGUAGE=") {
			env = append(env, v)
		}
	}
	cmd.Env = append(env, "LC_ALL=C", "LANG=C", "LANGUAGE=C")
	stdout := &cappedBuffer{limit: int(inventory.MaxSnapshotBytes)}
	stderr := &cappedBuffer{limit: 64 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	r := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			r.ExitCode = exit.ExitCode()
			return r, nil
		}
		return r, fmt.Errorf("%s command could not complete: %w", name, err)
	}
	return r, nil
}

// Do not persist raw native stderr: repository URLs can include credentials.
func commandFailure(name string, r Result) error {
	return fmt.Errorf("%s failed (exit %d); inspect package manager diagnostics locally", name, r.ExitCode)
}
