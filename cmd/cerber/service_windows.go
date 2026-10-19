// SPDX-License-Identifier: Apache-2.0
//go:build windows

package main

import (
	"context"
	"fmt"
	"github.com/rkislov/cerber/internal/agent"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"io"
	"strings"
	"time"
)

const serviceName = "CerberAgent"

type eventWriter struct{ log *eventlog.Log }

func (w eventWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if len(msg) > 3000 {
		msg = msg[:3000]
	}
	if msg != "" {
		if err := w.log.Info(1, msg); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}
func runService(args []string) (bool, error) {
	if len(args) < 2 || args[0] != "agent" || args[1] != "service-run" {
		return false, nil
	}
	if len(args) != 4 || args[2] != "-config" {
		return true, fmt.Errorf("usage: agent service-run -config ABSOLUTE_FILE")
	}
	isService, err := svc.IsWindowsService()
	if err != nil {
		return true, err
	}
	if !isService {
		return true, fmt.Errorf("service-run must be started by Windows SCM; use agent run -config in a console")
	}
	return true, svc.Run(serviceName, &windowsAgent{config: args[3]})
}

type windowsAgent struct{ config string }

func (h *windowsAgent) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending, WaitHint: 10000}
	log, err := eventlog.Open(serviceName)
	if err != nil {
		return true, 1
	}
	defer log.Close()
	config, err := agent.LoadConfig(h.config)
	if err == nil {
		err = config.ValidateInputs()
	}
	if err != nil {
		_ = log.Error(2, "agent configuration: "+err.Error())
		return true, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, config.Args(), io.Discard, eventWriter{log}) }()
	current := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	status <- current
	_ = log.Info(1, "Cerber agent started; running status does not imply SIEM connectivity")
	for {
		select {
		case err := <-done:
			if err != nil {
				_ = log.Error(2, err.Error())
				return true, 1
			}
			return false, 0
		case request, ok := <-requests:
			if !ok {
				cancel()
				return true, 1
			}
			switch request.Cmd {
			case svc.Interrogate:
				status <- current
			case svc.Stop, svc.Shutdown:
				cancel()
				current = svc.Status{State: svc.StopPending, WaitHint: 30000, CheckPoint: 1}
				status <- current
				ticker := time.NewTicker(5 * time.Second)
				defer ticker.Stop()
				timeout := time.NewTimer(30 * time.Second)
				defer timeout.Stop()
				for {
					select {
					case <-done:
						_ = log.Info(1, "Cerber agent stopped; unacknowledged reports remain queued")
						return false, 0
					case <-ticker.C:
						current.CheckPoint++
						status <- current
					case <-timeout.C:
						_ = log.Error(2, "Agent shutdown timed out; durable state will be recovered on restart")
						return true, 1
					}
				}
			}
		}
	}
}
