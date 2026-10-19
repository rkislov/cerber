// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/rkislov/cerber/internal/app"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/scanner/tcp"
	"github.com/rkislov/cerber/internal/storage/sqlite"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "cerber:", err)
		os.Exit(1)
	}
}

const usage = `Cerber — прототип сканера на Go
Использование: cerber [-db PATH] <ресурс> <команда> [параметры]
  asset add -ip ADDRESS [-name NAME]
  asset list
  target add -name NAME -assets ID,ID
  target list
  task create -target ID -ports 22,80,443 [-concurrency 16] [-timeout-ms 1000]
  task list
  task run -id ID
  task show -id ID
  events list [-after 0] [-limit 100]
Результаты — JSON. task run выполняется до завершения; Ctrl+C прерывает задачу.
Открытый TCP-порт не означает наличие уязвимости.
`

func flags(name string, errOut io.Writer) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(errOut)
	return f
}
func parse(f *flag.FlagSet, args []string) error {
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", f.Args())
	}
	return nil
}
func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	root := flags("cerber", errOut)
	dbPath := root.String("db", ".local/cerber.db", "SQLite database path")
	if err := root.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(out, usage)
			return nil
		}
		return err
	}
	args = root.Args()
	if len(args) == 0 {
		fmt.Fprint(out, usage)
		return nil
	}
	if len(args) < 2 {
		return fmt.Errorf("resource and command required\n%s", usage)
	}
	command := args[0] + " " + args[1]
	switch command {
	case "asset add", "asset list", "target add", "target list", "task create", "task list", "task run", "task show", "events list":
	default:
		return fmt.Errorf("unknown command %q", command)
	}
	if *dbPath != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(*dbPath), 0700); err != nil {
			return err
		}
		// Create private files before SQLite opens them (including a new database).
		f, err := os.OpenFile(*dbPath, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
	}
	store, err := sqlite.Open(ctx, *dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	svc := app.Service{Repo: store, Scanner: tcp.Scanner{}}
	f := flags(command, errOut)
	var result any
	switch command {
	case "asset add":
		ip := f.String("ip", "", "IP address")
		name := f.String("name", "", "asset name")
		if err = parse(f, args[2:]); err != nil {
			return err
		}
		result, err = svc.AddAsset(ctx, *ip, *name)
	case "asset list":
		if err = parse(f, args[2:]); err != nil {
			return err
		}
		result, err = store.Assets(ctx)
	case "target add":
		name := f.String("name", "", "target name")
		ids := f.String("assets", "", "comma-separated asset IDs")
		if err = parse(f, args[2:]); err != nil {
			return err
		}
		result, err = svc.AddTarget(ctx, *name, split(*ids))
	case "target list":
		if err = parse(f, args[2:]); err != nil {
			return err
		}
		result, err = store.Targets(ctx)
	case "task create":
		target := f.String("target", "", "target ID")
		ports := f.String("ports", "", "comma-separated TCP ports")
		concurrency := f.Int("concurrency", 16, "concurrent connections (1–64)")
		timeout := f.Int("timeout-ms", 1000, "per-connection timeout")
		if err = parse(f, args[2:]); err != nil {
			return err
		}
		pp, e := parsePorts(*ports)
		if e != nil {
			return e
		}
		result, err = svc.CreateTask(ctx, *target, domain.ScanConfig{Ports: pp, Concurrency: *concurrency, TimeoutMS: *timeout})
	case "task list":
		if err = parse(f, args[2:]); err != nil {
			return err
		}
		result, err = store.Tasks(ctx)
	case "task run", "task show":
		id := f.String("id", "", "task ID")
		if err = parse(f, args[2:]); err != nil {
			return err
		}
		if command == "task run" {
			if err = svc.Run(ctx, *id); err != nil {
				return err
			}
		}
		task, e := store.Task(ctx, *id)
		if e != nil {
			return e
		}
		observations, e := store.Observations(ctx, *id)
		if e != nil {
			return e
		}
		result = struct {
			Task         domain.Task          `json:"task"`
			Observations []domain.Observation `json:"observations"`
		}{task, observations}
	case "events list":
		after := f.Int64("after", 0, "exclusive event sequence cursor")
		limit := f.Int("limit", 100, "page size (1–1000)")
		if err = parse(f, args[2:]); err != nil {
			return err
		}
		result, err = store.Events(ctx, *after, *limit)
	}
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
func split(s string) []string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
func parsePorts(raw string) ([]uint16, error) {
	var ports []uint16
	for _, part := range split(raw) {
		p, err := strconv.ParseUint(part, 10, 16)
		if err != nil || p == 0 {
			return nil, fmt.Errorf("invalid TCP port %q", part)
		}
		ports = append(ports, uint16(p))
	}
	return ports, nil
}
