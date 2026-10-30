// SPDX-License-Identifier: Apache-2.0
package netsensor

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/rkislov/cerber/internal/agent"
	"github.com/rkislov/cerber/internal/eventcollector"
	"github.com/rkislov/cerber/internal/eventstore"
	"github.com/rkislov/cerber/internal/flowexport"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/telemetry"
)

const maxMessage = 12000

type Receiver struct {
	flows                                                              flowexport.Decoder
	flowTemplates, flowUnknown, flowWithdrawals, flowResets, flowStale atomic.Uint64
	spool                                                              eventcollector.Spool
	agent                                                              string
	mu                                                                 sync.Mutex
	received, rejected, stored                                         atomic.Uint64
	states                                                             map[string]telemetry.SourceHealth
}

func newReceiver(spool eventcollector.Spool, agent string) *Receiver {
	return &Receiver{spool: spool, agent: agent, states: map[string]telemetry.SourceHealth{}}
}

// accept commits before reading the next message on a stream. TCP itself has no
// durable application acknowledgement. UDP is best effort; rejected datagrams
// (including a full spool) are counted, never represented as delivered events.
func (r *Receiver) accept(ctx context.Context, i Input, peer string, data []byte, ports ...uint16) error {
	r.received.Add(1)
	fail := func(e error) error { r.rejected.Add(1); return e }
	v := telemetry.SensorEnvelope{Input: i.ID, Peer: peer, Transport: i.Protocol, Profile: i.Format}
	count := 1
	var decoded flowexport.Result
	if i.Format == "netflow9" || i.Format == "ipfix" {
		if len(ports) != 1 || ports[0] == 0 {
			return fail(telemetry.ErrInvalid)
		}
		ip, e := netip.ParseAddr(peer)
		if e != nil {
			return fail(e)
		}
		expected := uint16(9)
		if i.Format == "ipfix" {
			expected = 10
		}
		if len(data) < 2 || binary.BigEndian.Uint16(data) != expected {
			return fail(telemetry.ErrInvalid)
		}
		ttl := flowexport.DefaultTTL
		if i.TemplateTTLSeconds != 0 {
			ttl = time.Duration(i.TemplateTTLSeconds) * time.Second
		}
		decoded, e = r.flows.Decode(i.ID, netip.AddrPortFrom(ip, ports[0]), data, time.Now().UTC(), ttl)
		if e != nil {
			if errors.Is(e, flowexport.ErrStale) {
				r.flowStale.Add(1)
			}
			return fail(e)
		}
		r.flowTemplates.Add(uint64(decoded.Templates))
		r.flowUnknown.Add(uint64(decoded.UnknownSets))
		r.flowWithdrawals.Add(uint64(decoded.IgnoredWithdrawals))
		if decoded.Reset {
			r.flowResets.Add(1)
		}
		v.PeerPort = ports[0]
		count = len(decoded.Records)
	} else if i.Format == "netflow5" {
		flows, e := telemetry.DecodeNetFlow5(data)
		if e != nil {
			return fail(e)
		}
		v.Packet = data
		count = len(flows)
	} else {
		if len(data) == 0 || len(data) > maxMessage || !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
			return fail(telemetry.ErrInvalid)
		}
		v.Line = string(data)
		if i.Format == "suricata" && !json.Valid(data) {
			return fail(telemetry.ErrInvalid)
		}
	}
	var nonce [32]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return fail(e)
	}
	b := telemetry.Batch{SchemaVersion: 1, ID: hex.EncodeToString(nonce[:]), AgentID: r.agent}
	now := time.Now().UTC()
	for k := 0; k < count; k++ {
		v.Record = k
		if i.Format == "netflow9" || i.Format == "ipfix" {
			v.Flow = &decoded.Records[k]
		}
		p, e := json.Marshal(v)
		if e != nil {
			return fail(e)
		}
		cursor := b.ID + ":" + strconv.Itoa(k)
		b.Records = append(b.Records, telemetry.Raw{ID: telemetry.ID(b.ID, cursor), Source: i.Source(), Cursor: cursor, ObservedAt: now, Data: p})
	}
	if count > 0 {
		if e := b.Validate(); e != nil {
			return fail(e)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if count == 0 {
		state := telemetry.SourceHealth{Source: i.Source(), State: "ok", LastReadAt: &now}
		if decoded.UnknownSets > 0 {
			state.State = "error"
			state.Code = "source_read_failed"
		}
		r.states[i.Source()] = state
		return nil
	}
	previous, e := r.spool.SourceCursor(ctx, r.agent, i.Source())
	if e == nil {
		e = r.spool.Enqueue(ctx, b, i.Source(), previous, b.Records[len(b.Records)-1].Cursor)
	}
	state := telemetry.SourceHealth{Source: i.Source(), State: "ok", LastReadAt: &now}
	if e != nil {
		state.State = "error"
		state.Code = "spool_error"
		if errors.Is(e, telemetry.ErrFull) {
			state.State = "blocked"
			state.Code = "spool_full"
		}
		r.states[i.Source()] = state
		return fail(e)
	}
	if decoded.UnknownSets > 0 {
		state.State = "error"
		state.Code = "source_read_failed"
	}
	r.states[i.Source()] = state
	r.stored.Add(uint64(count))
	return nil
}

// ReadFrame implements RFC6587 octet-counting and newline framing with bounded
// header/message memory. A partial final line is not a complete frame.
func ReadFrame(r *bufio.Reader) ([]byte, error) {
	b, e := r.Peek(1)
	if e != nil {
		return nil, e
	}
	if b[0] >= '1' && b[0] <= '9' {
		n := 0
		for k := 0; k < 6; k++ {
			c, e := r.ReadByte()
			if e != nil {
				return nil, e
			}
			if c == ' ' {
				if n < 1 || n > maxMessage {
					return nil, telemetry.ErrInvalid
				}
				p := make([]byte, n)
				_, e = io.ReadFull(r, p)
				return p, e
			}
			if c < '0' || c > '9' {
				return nil, telemetry.ErrInvalid
			}
			n = n*10 + int(c-'0')
		}
		return nil, telemetry.ErrInvalid
	}
	p, e := r.ReadSlice('\n')
	if e != nil {
		return nil, e
	}
	p = p[:len(p)-1]
	if len(p) > 0 && p[len(p)-1] == '\r' {
		p = p[:len(p)-1]
	}
	if len(p) > maxMessage {
		return nil, telemetry.ErrInvalid
	}
	return p, nil
}

func tlsConfig(i Input) (*tls.Config, error) {
	cert, e := tls.LoadX509KeyPair(i.Cert, i.Key)
	if e != nil {
		return nil, e
	}
	pem, e := os.ReadFile(i.ClientCA)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("empty client CA")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}, nil
}

func (r *Receiver) serveStream(ctx context.Context, l net.Listener, i Input) error {
	var wg sync.WaitGroup
	slots := make(chan struct{}, 32)
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	defer wg.Wait()
	for {
		c, e := l.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		peer, e := netip.ParseAddrPort(c.RemoteAddr().String())
		if e != nil || !i.permits(peer.Addr()) {
			r.rejected.Add(1)
			c.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			r.rejected.Add(1)
			c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			defer c.Close()
			stop := context.AfterFunc(ctx, func() { c.Close() })
			defer stop()
			reader := bufio.NewReaderSize(c, maxMessage+2)
			for {
				_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
				data, e := ReadFrame(reader)
				if e != nil {
					if e != io.EOF && ctx.Err() == nil {
						r.rejected.Add(1)
					}
					return
				}
				if e = r.accept(ctx, i, peer.Addr().Unmap().String(), data); e != nil {
					return
				}
			}
		}()
	}
}

func (r *Receiver) serveUDP(ctx context.Context, c *net.UDPConn, i Input) error {
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	buf := make([]byte, maxMessage+1)
	for {
		n, peer, e := c.ReadFromUDPAddrPort(buf)
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		if n > maxMessage || !i.permits(peer.Addr()) {
			r.rejected.Add(1)
			continue
		}
		_ = r.accept(ctx, i, peer.Addr().Unmap().String(), buf[:n], peer.Port())
	}
}

func Run(ctx context.Context, c Config, log io.Writer) error {
	if e := c.Validate(); e != nil {
		return e
	}
	credentials, e := agent.LoadCredentials(c.Credentials)
	if e != nil {
		return e
	}
	var ca []byte
	if c.CACert != "" {
		ca, e = os.ReadFile(c.CACert)
		if e != nil {
			return e
		}
	}
	client, e := ingest.NewClient(c.Server, credentials, ca)
	if e != nil {
		return e
	}
	defer client.Close()
	spool, e := eventstore.Open(ctx, c.Spool)
	if e != nil {
		return e
	}
	defer spool.Close()
	r := newReceiver(spool, credentials.AgentID)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var closers []io.Closer
	defer func() {
		for _, c := range closers {
			c.Close()
		}
	}()
	var workers []func() error
	var files []eventcollector.Source
	for _, input := range c.Inputs {
		i := input
		r.states[i.Source()] = telemetry.SourceHealth{Source: i.Source(), State: "not_attempted"}
		if i.Protocol == "file" {
			files = append(files, eventcollector.LineFile{Path: i.Path, Source: i.Source(), Identity: i.ID, Encode: func(line string) ([]byte, error) {
				return json.Marshal(telemetry.SensorEnvelope{Input: i.ID, Peer: "local", Transport: "file", Profile: "suricata", Line: line})
			}})
			continue
		}
		if i.Protocol == "udp" {
			addr, e := net.ResolveUDPAddr("udp", i.Listen)
			if e != nil {
				return e
			}
			socket, e := net.ListenUDP("udp", addr)
			if e != nil {
				return e
			}
			closers = append(closers, socket)
			workers = append(workers, func() error { return r.serveUDP(ctx, socket, i) })
			continue
		}
		var tc *tls.Config
		if i.Protocol == "tls" {
			tc, e = tlsConfig(i)
			if e != nil {
				return e
			}
		}
		listener, e := net.Listen("tcp", i.Listen)
		if e != nil {
			return e
		}
		if tc != nil {
			listener = tls.NewListener(listener, tc)
		}
		closers = append(closers, listener)
		workers = append(workers, func() error { return r.serveStream(ctx, listener, i) })
	}
	// Startup is atomic: bind every configured listener before starting delivery.
	errCh := make(chan error, len(workers))
	var wg sync.WaitGroup
	for _, w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := w()
			if e != nil {
				errCh <- e
				cancel()
			}
		}()
	}
	defer func() { cancel(); wg.Wait() }()
	fmt.Fprintln(log, "sensor started; passive inputs; bounded durable queue")
	nextHeartbeat := time.Time{}
	var lastDelivery *time.Time
	for {
		cycleCtx, done := context.WithTimeout(ctx, 20*time.Second)
		h := eventcollector.Cycle(cycleCtx, spool, client, credentials.AgentID, files, func(e error) {
			if ctx.Err() == nil {
				fmt.Fprintf(log, "sensor delivery/source: %v\n", e)
			}
		})
		if h.LastDeliveryAt != nil {
			lastDelivery = h.LastDeliveryAt
		}
		h.LastDeliveryAt = lastDelivery
		r.mu.Lock()
		for _, s := range h.Sources {
			r.states[s.Source] = s
		}
		h.Sources = nil
		for _, name := range []string{"network:syslog", "network:netflow", "network:suricata"} {
			if s, ok := r.states[name]; ok {
				h.Sources = append(h.Sources, s)
			}
		}
		r.mu.Unlock()
		h.Enabled = true
		if !time.Now().Before(nextHeartbeat) {
			_, e = client.Heartbeat(cycleCtx, ingest.Heartbeat{SchemaVersion: 1, AgentID: credentials.AgentID, ObservedAt: time.Now().UTC(), Platform: runtime.GOOS, Architecture: runtime.GOARCH, CollectionStatus: "not_attempted", DeliveryStatus: "not_attempted", Events: &h})
			if e != nil && ctx.Err() == nil {
				fmt.Fprintf(log, "sensor heartbeat: %v\n", e)
			}
			fmt.Fprintf(log, "sensor counters received=%d stored_records=%d rejected=%d queue_batches=%d queue_bytes=%d delivery=%s\n", r.received.Load(), r.stored.Load(), r.rejected.Load(), h.QueueBatches, h.QueueBytes, h.Delivery)
			fmt.Fprintf(log, "flow templates=%d unknown_sets=%d ignored_udp_withdrawals=%d resets=%d stale_packets=%d\n", r.flowTemplates.Load(), r.flowUnknown.Load(), r.flowWithdrawals.Load(), r.flowResets.Load(), r.flowStale.Load())
			nextHeartbeat = time.Now().Add(time.Minute)
		}
		done()
		t := time.NewTimer(time.Second)
		select {
		case e := <-errCh:
			t.Stop()
			return e
		case <-ctx.Done():
			t.Stop()
			select {
			case e := <-errCh:
				return e
			default:
				return nil
			}
		case <-t.C:
		}
	}
}
