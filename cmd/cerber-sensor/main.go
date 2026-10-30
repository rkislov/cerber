// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/rkislov/cerber/internal/netsensor"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	path := flag.String("config", "", "absolute sensor configuration path")
	check := flag.Bool("check", false, "validate configuration without opening listeners")
	flag.Parse()
	c, e := netsensor.Load(*path)
	if e == nil && !*check {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		e = netsensor.Run(ctx, c, os.Stderr)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
