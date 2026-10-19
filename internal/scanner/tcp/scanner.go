// SPDX-License-Identifier: Apache-2.0
package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/ports"
)

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}
type Scanner struct{ Dialer Dialer }

var _ ports.Scanner = Scanner{}

type probe struct {
	host domain.Host
	port uint16
}

func (s Scanner) Scan(ctx context.Context, t domain.Task, emit func(domain.Observation) error) error {
	config, err := t.Config.Normalize(len(t.Hosts))
	if err != nil {
		return err
	}
	for _, h := range t.Hosts {
		ip, err := domain.CanonicalIP(h.IP)
		if err != nil {
			return err
		}
		if ip != h.IP || h.AssetID == "" {
			return fmt.Errorf("invalid host snapshot")
		}
	}
	if emit == nil {
		return fmt.Errorf("nil observation sink")
	}
	dialer := s.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan probe)
	results := make(chan domain.Observation, config.Concurrency)
	var wg sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				if workCtx.Err() != nil {
					return
				}
				attempt, done := context.WithTimeout(workCtx, time.Duration(config.TimeoutMS)*time.Millisecond)
				conn, err := dialer.DialContext(attempt, "tcp", net.JoinHostPort(p.host.IP, strconv.Itoa(int(p.port))))
				if conn != nil {
					conn.Close()
				}
				done()
				// Cancellation is not evidence of a closed/filtered port.
				if workCtx.Err() != nil {
					return
				}
				o := domain.Observation{TaskID: t.ID, AssetID: p.host.AssetID, IP: p.host.IP, Port: p.port,
					Protocol: "tcp", State: domain.Open, ObservedAt: time.Now().UTC()}
				if err != nil {
					o.Detail = err.Error()
					var ne net.Error
					switch {
					case errors.Is(err, syscall.ECONNREFUSED):
						o.State = domain.Closed
					case errors.Is(err, context.DeadlineExceeded):
						o.State = domain.Timeout
					case errors.As(err, &ne) && ne.Timeout():
						o.State = domain.Timeout
					default:
						o.State = domain.ProbeError
					}
				}
				select {
				case results <- o:
				case <-workCtx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, h := range t.Hosts {
			for _, p := range config.Ports {
				select {
				case jobs <- probe{h, p}:
				case <-workCtx.Done():
					return
				}
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	var sinkErr error
	for o := range results {
		if sinkErr == nil {
			if err := emit(o); err != nil {
				sinkErr = err
				cancel()
			}
		}
	}
	if sinkErr != nil {
		return sinkErr
	}
	return ctx.Err()
}
