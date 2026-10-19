package tcp

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/rkislov/cerber/internal/domain"
)

func task(ports ...uint16) domain.Task {
	return domain.Task{ID: "task", Hosts: []domain.Host{{AssetID: "asset", IP: "127.0.0.1"}}, Config: domain.ScanConfig{Ports: ports, Concurrency: 2, TimeoutMS: 100}}
}
func TestRealListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	var results []domain.Observation
	err = (Scanner{}).Scan(context.Background(), task(port), func(o domain.Observation) error { results = append(results, o); return nil })
	if err != nil || len(results) != 1 || results[0].State != domain.Open {
		t.Fatalf("results=%+v err=%v", results, err)
	}
	if results[0].TaskID != "task" || results[0].AssetID != "asset" || results[0].ObservedAt.IsZero() {
		t.Fatal("missing evidence metadata")
	}
}

type dialFunc func(context.Context, string, string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}
func TestClassifiesEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want domain.PortState
	}{
		{"refused", syscall.ECONNREFUSED, domain.Closed},
		{"timeout", context.DeadlineExceeded, domain.Timeout},
		{"unreachable", syscall.ENETUNREACH, domain.ProbeError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Scanner{Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) { return nil, tc.err })}
			var got domain.PortState
			if err := s.Scan(context.Background(), task(22), func(o domain.Observation) error { got = o.State; return nil }); err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}
func TestBoundedConcurrencyAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{}, 2)
	var active, max atomic.Int32
	s := Scanner{Dialer: dialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := max.Load(); n > old; old = max.Load() {
			if max.CompareAndSwap(old, n) {
				break
			}
		}
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	})}
	finished := make(chan error, 1)
	var emitted atomic.Int32
	go func() {
		finished <- s.Scan(ctx, task(1, 2, 3, 4), func(domain.Observation) error { emitted.Add(1); return nil })
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("workers did not start")
		}
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation hung")
	}
	if max.Load() > 2 || active.Load() != 0 || emitted.Load() != 0 {
		t.Fatalf("max=%d active=%d emitted=%d", max.Load(), active.Load(), emitted.Load())
	}
}
func TestSinkFailureStopsWorkers(t *testing.T) {
	sentinel := errors.New("disk full")
	s := Scanner{Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) { return nil, syscall.ECONNREFUSED })}
	err := s.Scan(context.Background(), task(1, 2, 3, 4), func(domain.Observation) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("got %v", err)
	}
}
func TestIPv6AddressFormatting(t *testing.T) {
	var address string
	s := Scanner{Dialer: dialFunc(func(_ context.Context, _, addr string) (net.Conn, error) {
		address = addr
		return nil, syscall.ECONNREFUSED
	})}
	input := task(443)
	input.Hosts[0].IP = "::1"
	if err := s.Scan(context.Background(), input, func(domain.Observation) error { return nil }); err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil || port != strconv.Itoa(443) {
		t.Fatal(address, err)
	}
}
