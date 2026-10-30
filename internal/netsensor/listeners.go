// SPDX-License-Identifier: Apache-2.0
package netsensor

import (
	"context"
	"github.com/rkislov/cerber/internal/sensorstate"
	"net"
	"net/netip"
	"sync"
)

type flowSocket struct {
	conn   *net.UDPConn
	cancel context.CancelFunc
	once   sync.Once
}

func (s *flowSocket) close() {
	s.once.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		s.conn.Close()
	})
}
func definitions(inputs []Input) []sensorstate.Definition {
	result := make([]sensorstate.Definition, 0, len(inputs))
	for _, i := range inputs {
		result = append(result, sensorstate.Definition{ID: i.ID, Format: i.Format, Protocol: i.Protocol, Listen: i.Listen})
	}
	return result
}
func resolveInputs(base []Input, p sensorstate.Policy) ([]Input, error) {
	defs, e := sensorstate.Resolve(p.Inputs, definitions(base))
	if e != nil {
		return nil, e
	}
	result := make([]Input, 0, len(defs))
	for _, d := range defs {
		i := Input{ID: d.ID, Format: d.Format, Protocol: d.Protocol, Listen: d.Listen}
		for _, b := range base {
			if b.ID == d.ID {
				i = b
				i.Format = d.Format
				i.Protocol = d.Protocol
				i.Listen = d.Listen
				break
			}
		}
		for _, c := range p.Inputs {
			if c.ID == d.ID {
				i.Allow = append([]string(nil), c.Allow...)
				i.TemplateTTLSeconds = c.TemplateTTLSeconds
				break
			}
		}
		result = append(result, i)
	}
	return result, nil
}
func (r *Receiver) enabled(id string) bool {
	for _, c := range r.policy.Inputs {
		if c.ID == id {
			return !c.Removed && c.Enabled
		}
	}
	return true
}
func bindFlow(listen string) (*net.UDPConn, error) {
	addr, e := netip.ParseAddrPort(listen)
	if e != nil {
		return nil, e
	}
	network := "udp6"
	if addr.Addr().Is4() {
		network = "udp4"
	}
	return net.ListenUDP(network, net.UDPAddrFromAddrPort(addr))
}

// Prepare binds every NEW endpoint before any old socket is removed. Existing
// endpoints can be reassigned between IDs/formats without SO_REUSEPORT races.
// Overlapping wildcard changes need a separate delete then create operation.
func (r *Receiver) prepareFlows(inputs []Input) (map[string]*flowSocket, string, error) {
	pending := map[string]*flowSocket{}
	for _, i := range inputs {
		if !sensorstate.Flow(i.Format) {
			continue
		}
		if r.flowSockets[i.Listen] != nil {
			continue
		}
		c, e := bindFlow(i.Listen)
		if e != nil {
			for _, s := range pending {
				s.close()
			}
			return nil, i.ID, e
		}
		pending[i.Listen] = &flowSocket{conn: c}
	}
	return pending, "", nil
}
func (r *Receiver) commitFlows(inputs []Input, pending map[string]*flowSocket) {
	wanted := map[string]bool{}
	for _, i := range inputs {
		if sensorstate.Flow(i.Format) {
			wanted[i.Listen] = true
		}
	}
	for address, s := range r.flowSockets {
		if !wanted[address] {
			delete(r.flowSockets, address)
			s.close()
		}
	}
	for address, s := range pending {
		child, cancel := context.WithCancel(r.flowCtx)
		s.cancel = cancel
		r.flowSockets[address] = s
		r.flowWG.Add(1)
		go func() { defer r.flowWG.Done(); r.readFlow(child, address, s) }()
	}
	r.flowReady = true
}
func (r *Receiver) readFlow(ctx context.Context, address string, socket *flowSocket) {
	buf := make([]byte, maxMessage+1)
	stop := context.AfterFunc(ctx, func() { socket.conn.Close() })
	defer stop()
	for {
		n, peer, e := socket.conn.ReadFromUDPAddrPort(buf)
		if e != nil {
			if ctx.Err() == nil && r.flowFailure != nil {
				r.flowFailure(e)
			}
			return
		}
		r.controlMu.RLock()
		if r.flowSockets[address] == socket {
			for _, i := range r.activeInputs {
				if sensorstate.Flow(i.Format) && i.Listen == address {
					_ = r.receiveLocked(ctx, i, peer, buf[:n])
					break
				}
			}
		}
		r.controlMu.RUnlock()
	}
}
func (r *Receiver) startFlows(ctx context.Context, failure func(error)) error {
	r.controlMu.Lock()
	defer r.controlMu.Unlock()
	r.flowCtx = ctx
	r.flowFailure = failure
	r.flowSockets = map[string]*flowSocket{}
	pending, id, e := r.prepareFlows(r.activeInputs)
	if e != nil {
		r.configError = "policy_bind_failed"
		r.configErrorInput = id
		r.flowReady = false
		return e
	}
	r.commitFlows(r.activeInputs, pending)
	return nil
}
func (r *Receiver) stopFlows() {
	r.controlMu.Lock()
	for address, s := range r.flowSockets {
		delete(r.flowSockets, address)
		s.close()
	}
	r.flowCtx = nil
	r.controlMu.Unlock()
	r.flowWG.Wait()
}
