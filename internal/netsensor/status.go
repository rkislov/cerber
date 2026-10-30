// SPDX-License-Identifier: Apache-2.0
package netsensor

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/flowexport"
	"github.com/rkislov/cerber/internal/sensorstate"
	"github.com/rkislov/cerber/internal/telemetry"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"
)

type inputMetrics struct {
	status   sensorstate.Input
	previous sensorstate.Counters
}
type cachedPolicy struct {
	Agent       string             `json:"agent"`
	Fingerprint string             `json:"fingerprint"`
	Policy      sensorstate.Policy `json:"policy"`
}

func statusInput(i Input) sensorstate.Input {
	ttl := i.TemplateTTLSeconds
	if ttl == 0 && (i.Format == "netflow9" || i.Format == "ipfix") {
		ttl = 900
	}
	allow := append([]string(nil), i.Allow...)
	for k, s := range allow {
		if p, e := netip.ParsePrefix(s); e == nil {
			allow[k] = p.Masked().String()
		}
	}
	state := "listening"
	if i.Protocol == "file" {
		state = "not_attempted"
	}
	return sensorstate.Input{ID: i.ID, Format: i.Format, Protocol: i.Protocol, Listen: i.Listen, Enabled: true, Allow: allow, TemplateTTLSeconds: ttl, State: state, Exporters: []sensorstate.Exporter{}}
}
func (r *Receiver) configure(c Config) error {
	data, _ := json.Marshal(c.Inputs)
	sum := sha256.Sum256(data)
	r.fingerprint = hex.EncodeToString(sum[:])
	r.policyPath = c.Spool + ".sensor-policy.json"
	r.localInputs = append([]Input(nil), c.Inputs...)
	var resolveErr error
	r.activeInputs, resolveErr = resolveInputs(c.Inputs, sensorstate.Policy{})
	if resolveErr != nil {
		return resolveErr
	}
	r.configured = true
	r.metricsMu.Lock()
	for _, i := range r.activeInputs {
		r.metrics[i.ID] = &inputMetrics{status: statusInput(i)}
		r.states[i.Source()] = telemetry.SourceHealth{Source: i.Source(), State: "not_attempted"}
	}
	r.metricsMu.Unlock()
	b, e := os.ReadFile(r.policyPath)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	var cached cachedPolicy
	if len(b) > 65536 || json.Unmarshal(b, &cached) != nil || cached.Agent != r.agent || cached.Fingerprint != r.fingerprint {
		return errors.New("sensor policy cache does not match local inputs; reconcile the policy cache before startup")
	}
	return r.applyPolicy(cached.Policy, false)
}

// A cached policy is committed before it can change admission. After a restart,
// the last acknowledged pause/allowlist is in force even with SIEM unavailable.
func (r *Receiver) applyPolicy(p sensorstate.Policy, persist bool) error {
	r.controlMu.Lock()
	defer r.controlMu.Unlock()
	if p.Revision < 1 {
		return sensorstate.ErrInvalid
	}
	if p.Revision < r.policy.Revision || p.Revision == r.policy.Revision && (r.flowCtx == nil || r.flowReady) {
		return nil
	}
	if p.Monitor != nil {
		m := *p.Monitor
		m.Config.Watches = append([]sensorstate.Watch(nil), p.Monitor.Config.Watches...)
		p.Monitor = &m
	}
	p.Inputs = append([]sensorstate.Control(nil), p.Inputs...)
	for k := range p.Inputs {
		p.Inputs[k].Allow = append([]string(nil), p.Inputs[k].Allow...)
	}
	r.metricsMu.Lock()
	defer r.metricsMu.Unlock()
	base := r.localInputs
	if !r.configured {
		for _, m := range r.metrics {
			v := m.status
			base = append(base, Input{ID: v.ID, Format: v.Format, Protocol: v.Protocol, Listen: v.Listen, Allow: v.Allow, TemplateTTLSeconds: v.TemplateTTLSeconds})
		}
	}
	if p.Monitor != nil && (p.Monitor.Config.Validate() != nil || p.Monitor.Revision < 1 || p.Monitor.Revision > p.Revision || p.Monitor.UpdatedAt.IsZero()) {
		return sensorstate.ErrInvalid
	}
	next, e := resolveInputs(base, p)
	if e != nil || p.UpdatedAt.IsZero() {
		r.configError = "policy_invalid"
		r.configErrorInput = ""
		return sensorstate.ErrInvalid
	}
	var pending map[string]*flowSocket
	if r.flowCtx != nil {
		var id string
		pending, id, e = r.prepareFlows(next)
		if e != nil {
			r.configError = "policy_bind_failed"
			r.configErrorInput = id
			return e
		}
	}
	if persist {
		b, e := json.Marshal(cachedPolicy{r.agent, r.fingerprint, p})
		if e == nil {
			e = writePolicy(r.policyPath, b)
		}
		if e != nil {
			for _, socket := range pending {
				socket.close()
			}
			r.configErrorInput = ""
			r.configError = "policy_persist_failed"
			return e
		}
	}
	// Admission and routes switch under one lock, after durable persistence.
	desired := map[string]bool{}
	for _, input := range next {
		id := input.ID
		desired[id] = true
		m := r.metrics[id]
		if m == nil {
			r.metrics[id] = &inputMetrics{status: statusInput(input)}
			continue
		}
		var oldInput *Input
		for k := range r.activeInputs {
			if r.activeInputs[k].ID == id {
				oldInput = &r.activeInputs[k]
				break
			}
		}
		if oldInput == nil || !reflect.DeepEqual(*oldInput, input) || r.enabled(id) != policyEnabled(p, id) {
			r.flows.ForgetInput(id)
			m.status.State = "listening"
			m.status.Format = input.Format
			m.status.Protocol = input.Protocol
			m.status.Listen = input.Listen
		}
	}
	for id := range r.metrics {
		if !desired[id] {
			delete(r.metrics, id)
			r.flows.ForgetInput(id)
		}
	}
	r.activeInputs = next
	r.policy = p
	r.syncWatches(time.Now().UTC())
	r.configError = ""
	r.configErrorInput = ""
	r.mu.Lock()
	sources := map[string]bool{}
	for _, input := range next {
		sources[input.Source()] = true
		if _, ok := r.states[input.Source()]; !ok {
			r.states[input.Source()] = telemetry.SourceHealth{Source: input.Source(), State: "not_attempted"}
		}
	}
	for name := range r.states {
		if !sources[name] {
			delete(r.states, name)
		}
	}
	r.mu.Unlock()
	if r.flowCtx != nil {
		r.commitFlows(next, pending)
	}

	return nil
}
func writePolicy(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".sensor-policy-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	return publishPolicy(name, path)
}
func policyEnabled(p sensorstate.Policy, id string) bool {
	for _, c := range p.Inputs {
		if c.ID == id {
			return !c.Removed && c.Enabled
		}
	}
	return true
}
func (r *Receiver) effective(i Input) (Input, bool) {
	if r.configured {
		for _, active := range r.activeInputs {
			if active.ID == i.ID {
				return active, r.enabled(i.ID)
			}
		}
		return i, false
	}
	for _, p := range r.policy.Inputs {
		if p.ID == i.ID {
			i.Allow = append([]string(nil), p.Allow...)
			i.TemplateTTLSeconds = p.TemplateTTLSeconds
			return i, p.Enabled
		}
	}
	return i, true
}
func (r *Receiver) receive(ctx context.Context, i Input, peer netip.AddrPort, data []byte) error {
	r.controlMu.RLock()
	defer r.controlMu.RUnlock()
	return r.receiveLocked(ctx, i, peer, data)
}
func (r *Receiver) receiveLocked(ctx context.Context, i Input, peer netip.AddrPort, data []byte) error {
	i, enabled := r.effective(i)
	code := ""
	if !enabled {
		code = "input_paused"
	} else if !i.permits(peer.Addr()) {
		code = "peer_denied"
	} else if len(data) > maxMessage {
		code = "message_too_large"
	}
	if code != "" {
		r.rejected.Add(1)
		r.record(i, peer.Addr().Unmap().String(), peer.Port(), data, flowexport.Result{}, 0, code, false)
		return telemetry.ErrInvalid
	}
	return r.accept(ctx, i, peer.Addr().Unmap().String(), data, peer.Port())
}
func (r *Receiver) record(i Input, peer string, port uint16, data []byte, result flowexport.Result, stored int, code string, trackPeer bool) {
	now := time.Now().UTC()
	r.metricsMu.Lock()
	defer r.metricsMu.Unlock()
	m := r.metrics[i.ID]
	if m == nil {
		m = &inputMetrics{status: statusInput(i)}
		r.metrics[i.ID] = m
	}
	add := sensorstate.Counters{Messages: 1, Bytes: uint64(len(data)), Stored: uint64(stored), Templates: uint64(result.Templates), UnknownSets: uint64(result.UnknownSets), Withdrawals: uint64(result.IgnoredWithdrawals)}
	if result.Reset {
		add.Resets = 1
	}
	if code != "" {
		add.Rejected = 1
	}
	if code == "stale_packet" {
		add.Stale = 1
	}
	addCounters(&m.status.Counters, add)
	m.status.LastMessageAt = &now
	m.status.State = "receiving"
	if code != "" {
		m.status.State = "error"
		m.status.LastError = code
		m.status.LastErrorAt = &now
	}
	// Only admitted flow peers enter the bounded exporter list. UDP source claims
	// are observations, not authenticated device identities.
	if trackPeer {
		for key, w := range r.watches {
			if w.Input == i.ID && (w.Peer == "" || w.Peer == peer) {
				at := now
				w.LastSeen = &at
				r.watches[key] = w
			}
		}
	}
	if trackPeer && sensorstate.Flow(i.Format) {
		domain := uint32(0)
		if i.Format == "netflow9" && len(data) >= 20 {
			domain = binary.BigEndian.Uint32(data[16:20])
		}
		if i.Format == "ipfix" && len(data) >= 16 {
			domain = binary.BigEndian.Uint32(data[12:16])
		}
		index := -1
		for k, p := range m.status.Exporters {
			if p.Peer == peer && p.Port == port && p.Domain == domain {
				index = k
				break
			}
		}
		if index < 0 {
			if len(m.status.Exporters) < 8 {
				m.status.Exporters = append(m.status.Exporters, sensorstate.Exporter{})
				index = len(m.status.Exporters) - 1
			} else {
				index = 0
				for k, p := range m.status.Exporters {
					if p.LastSeen.Before(m.status.Exporters[index].LastSeen) {
						index = k
					}
				}
				m.status.ExportersOverflow++
			}
			m.status.Exporters[index] = sensorstate.Exporter{Peer: peer, Port: port, Domain: domain}
		}
		p := &m.status.Exporters[index]
		p.LastSeen = now
		addCounters(&p.Counters, add)
	}
}
func addCounters(c *sensorstate.Counters, v sensorstate.Counters) {
	c.Messages += v.Messages
	c.Bytes += v.Bytes
	c.Stored += v.Stored
	c.Rejected += v.Rejected
	c.Templates += v.Templates
	c.UnknownSets += v.UnknownSets
	c.Withdrawals += v.Withdrawals
	c.Resets += v.Resets
	c.Stale += v.Stale
}
func errorCode(e error) string {
	switch {
	case e == nil:
		return ""
	case errors.Is(e, flowexport.ErrStale):
		return "stale_packet"
	case errors.Is(e, flowexport.ErrLimit):
		return "decoder_limit"
	case errors.Is(e, telemetry.ErrFull):
		return "spool_full"
	default:
		return "invalid_packet"
	}
}
func (r *Receiver) snapshot(inputs []Input) sensorstate.Status {
	r.controlMu.RLock()
	defer r.controlMu.RUnlock()
	r.metricsMu.Lock()
	defer r.metricsMu.Unlock()
	now := time.Now().UTC()
	if r.configured {
		inputs = r.activeInputs
	}
	s := sensorstate.Status{MonitoringVersion: 1, InputManagement: 1, BaseInputs: definitions(r.localInputs), ConfigErrorInput: r.configErrorInput, StartedAt: r.started, ObservedAt: now, SampleSeconds: now.Sub(r.sampleAt).Seconds(), AppliedRevision: r.policy.Revision, ConfigError: r.configError, Inputs: []sensorstate.Input{}}
	if r.flowCtx != nil && !r.flowReady {
		s.AppliedRevision = 0
	}
	for _, local := range inputs {
		m := r.metrics[local.ID]
		if m == nil {
			continue
		}
		i := m.status
		if i.LastMessageAt != nil {
			at := *i.LastMessageAt
			i.LastMessageAt = &at
		}
		if i.LastErrorAt != nil {
			at := *i.LastErrorAt
			i.LastErrorAt = &at
		}
		i.Allow = append([]string(nil), i.Allow...)
		i.Exporters = append([]sensorstate.Exporter(nil), i.Exporters...)
		effective, enabled := r.effective(local)
		i.Allow = statusInput(effective).Allow
		i.TemplateTTLSeconds = statusInput(effective).TemplateTTLSeconds
		i.Enabled = enabled
		if r.flowCtx != nil && sensorstate.Flow(i.Format) && r.flowSockets[i.Listen] == nil {
			i.State = "error"
			i.LastError = "listener_unavailable"
			at := now
			i.LastErrorAt = &at
		}
		if !enabled {
			i.State = "paused"
		}
		i.IntervalMessages = i.Counters.Messages - m.previous.Messages
		i.IntervalBytes = i.Counters.Bytes - m.previous.Bytes
		m.previous = i.Counters
		sort.Slice(i.Exporters, func(a, b int) bool { return i.Exporters[a].LastSeen.After(i.Exporters[b].LastSeen) })
		s.Inputs = append(s.Inputs, i)
	}
	for _, w := range r.watches {
		if w.LastSeen != nil {
			at := *w.LastSeen
			w.LastSeen = &at
		}
		s.Watches = append(s.Watches, w)
	}
	sort.Slice(s.Watches, func(i, j int) bool {
		return sensorstate.WatchKey(s.Watches[i].Input, s.Watches[i].Peer) < sensorstate.WatchKey(s.Watches[j].Input, s.Watches[j].Peer)
	})
	r.sampleAt = now
	return s
}

// Keep configured exporter liveness independently of the bounded recent-session list.
// Called with controlMu and metricsMu held, before new readers start.
func (r *Receiver) syncWatches(now time.Time) {
	next := map[string]sensorstate.WatchStatus{}
	if r.policy.Monitor != nil && r.policy.Monitor.Config.Enabled {
		for _, w := range r.policy.Monitor.Config.Watches {
			for _, i := range r.activeInputs {
				if i.ID != w.Input || i.Protocol == "file" || !r.enabled(i.ID) {
					continue
				}
				key := sensorstate.WatchKey(w.Input, w.Peer)
				v, ok := r.watches[key]
				if !ok {
					v = sensorstate.WatchStatus{Input: w.Input, Peer: w.Peer, Since: now}
				}
				next[key] = v
			}
		}
	}
	r.watches = next
}
