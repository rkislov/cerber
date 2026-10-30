// SPDX-License-Identifier: Apache-2.0
// Package sensorstate defines bounded sensor status and central input controls.
package sensorstate

import (
	"errors"
	"github.com/rkislov/cerber/internal/telemetry"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

var ErrInvalid = errors.New("invalid sensor configuration")
var ErrConflict = errors.New("sensor revision conflict")
var ErrNotFound = errors.New("sensor not found")

type Control struct {
	Format             string   `json:"format,omitempty"`
	Listen             string   `json:"listen,omitempty"`
	Removed            bool     `json:"removed,omitempty"`
	ID                 string   `json:"id"`
	Enabled            bool     `json:"enabled"`
	Allow              []string `json:"allow"`
	TemplateTTLSeconds int      `json:"template_ttl_seconds"`
}
type Policy struct {
	Monitor   *MonitorPolicy `json:"monitor,omitempty"`
	Revision  int64          `json:"revision"`
	Inputs    []Control      `json:"inputs"`
	UpdatedAt time.Time      `json:"updated_at"`
	UpdatedBy string         `json:"updated_by"`
}
type Change struct {
	Monitor          *MonitorConfig `json:"monitor,omitempty"`
	AgentID          string         `json:"agent_id"`
	ExpectedRevision int64          `json:"expected_revision"`
	Inputs           []Control      `json:"inputs"`
}
type Counters struct {
	Messages    uint64 `json:"messages"`
	Bytes       uint64 `json:"bytes"`
	Stored      uint64 `json:"stored"`
	Rejected    uint64 `json:"rejected"`
	Templates   uint64 `json:"templates"`
	UnknownSets uint64 `json:"unknown_sets"`
	Withdrawals uint64 `json:"withdrawals"`
	Resets      uint64 `json:"resets"`
	Stale       uint64 `json:"stale"`
}
type Exporter struct {
	Peer     string    `json:"peer"`
	Port     uint16    `json:"port"`
	Domain   uint32    `json:"domain"`
	LastSeen time.Time `json:"last_seen"`
	Counters Counters  `json:"counters"`
}
type Input struct {
	ID                 string     `json:"id"`
	Format             string     `json:"format"`
	Protocol           string     `json:"protocol"`
	Listen             string     `json:"listen,omitempty"`
	Enabled            bool       `json:"enabled"`
	Allow              []string   `json:"allow,omitempty"`
	TemplateTTLSeconds int        `json:"template_ttl_seconds,omitempty"`
	State              string     `json:"state"`
	Counters           Counters   `json:"counters"`
	LastMessageAt      *time.Time `json:"last_message_at,omitempty"`
	LastError          string     `json:"last_error,omitempty"`
	LastErrorAt        *time.Time `json:"last_error_at,omitempty"`
	Exporters          []Exporter `json:"exporters"`
	ExportersOverflow  uint64     `json:"exporters_overflow"`
	IntervalMessages   uint64     `json:"interval_messages"`
	IntervalBytes      uint64     `json:"interval_bytes"`
}
type Definition struct {
	ID       string `json:"id"`
	Format   string `json:"format"`
	Protocol string `json:"protocol"`
	Listen   string `json:"listen,omitempty"`
}
type Status struct {
	SFlowVersion      int           `json:"sflow_version,omitempty"`
	MonitoringVersion int           `json:"monitoring_version,omitempty"`
	Watches           []WatchStatus `json:"watches,omitempty"`
	InputManagement   int           `json:"input_management,omitempty"`
	BaseInputs        []Definition  `json:"base_inputs,omitempty"`
	ConfigErrorInput  string        `json:"config_error_input,omitempty"`
	StartedAt         time.Time     `json:"started_at"`
	ObservedAt        time.Time     `json:"observed_at"`
	SampleSeconds     float64       `json:"sample_seconds"`
	AppliedRevision   int64         `json:"applied_revision"`
	ConfigError       string        `json:"config_error,omitempty"`
	Inputs            []Input       `json:"inputs"`
}

func Flow(format string) bool {
	return format == "sflow5" || format == "netflow5" || format == "netflow9" || format == "ipfix"
}
func ValidAllow(allow []string) bool {
	if len(allow) < 1 || len(allow) > 128 {
		return false
	}
	seen := map[string]bool{}
	for _, s := range allow {
		p, e := netip.ParsePrefix(s)
		if e != nil || p.Addr().Is4In6() || p != p.Masked() || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

// ValidateControls accepts legacy admission overrides and explicit listener
// definitions. Tombstones only suppress local flow inputs; centrally created
// inputs are deleted by removing their definition from the desired policy.
func ValidateControls(inputs []Control) error {
	if len(inputs) > 16 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, i := range inputs {
		if !telemetry.AgentIdentifier(i.ID) || seen[i.ID] {
			return ErrInvalid
		}
		seen[i.ID] = true
		if i.Removed {
			if i.Format != "" || i.Listen != "" || i.Enabled || len(i.Allow) != 0 || i.TemplateTTLSeconds != 0 {
				return ErrInvalid
			}
			continue
		}
		if !ValidAllow(i.Allow) || i.TemplateTTLSeconds != 0 && (i.TemplateTTLSeconds < 60 || i.TemplateTTLSeconds > 86400) {
			return ErrInvalid
		}
		if i.Format != "" || i.Listen != "" {
			if !Flow(i.Format) || !ValidListen(i.Listen) || (i.Format == "netflow5" || i.Format == "sflow5") && i.TemplateTTLSeconds != 0 {
				return ErrInvalid
			}
		}
	}
	return nil
}
func ValidListen(s string) bool {
	a, e := netip.ParseAddrPort(s)
	return e == nil && a.Port() != 0 && a.Addr().Zone() == "" && !a.Addr().Is4In6() && !a.Addr().IsMulticast() && a.Addr().String() != "255.255.255.255"
}

// Overlap uses explicit IPv4/IPv6-only UDP sockets. TCP on the same port is
// independent; wildcard/specific UDP bindings cannot coexist on one family.
func Overlap(a, b Definition) bool {
	if a.Protocol != "udp" || b.Protocol != "udp" {
		return false
	}
	x, ex := netip.ParseAddrPort(a.Listen)
	y, ey := netip.ParseAddrPort(b.Listen)
	return ex == nil && ey == nil && x.Port() == y.Port() && x.Addr().Is4() == y.Addr().Is4() && (x.Addr().IsUnspecified() || y.Addr().IsUnspecified() || x.Addr() == y.Addr())
}
func Definitions(inputs []Input) []Definition {
	v := make([]Definition, 0, len(inputs))
	for _, i := range inputs {
		v = append(v, Definition{i.ID, i.Format, i.Protocol, i.Listen})
	}
	return v
}
func Resolve(controls []Control, base []Definition) ([]Definition, error) {
	if ValidateControls(controls) != nil || len(base) > 8 {
		return nil, ErrInvalid
	}
	result := append([]Definition(nil), base...)
	for k, i := range result {
		if i.Listen != "" {
			if a, e := netip.ParseAddrPort(i.Listen); e == nil {
				result[k].Listen = a.String()
			}
		}
	}
	local := map[string]Definition{}
	for _, i := range base {
		if !telemetry.AgentIdentifier(i.ID) {
			return nil, ErrInvalid
		}
		if _, ok := local[i.ID]; ok {
			return nil, ErrInvalid
		}
		local[i.ID] = i
	}
	for _, c := range controls {
		original, exists := local[c.ID]
		if exists && (!Flow(original.Format) || original.Protocol != "udp") {
			return nil, ErrInvalid
		}
		if c.Removed {
			if !exists {
				return nil, ErrInvalid
			}
			for k, i := range result {
				if i.ID == c.ID {
					result = append(result[:k], result[k+1:]...)
					break
				}
			}
			continue
		}
		if c.Format == "" {
			if !exists || (original.Format == "netflow5" || original.Format == "sflow5") && c.TemplateTTLSeconds != 0 {
				return nil, ErrInvalid
			}
			continue
		}
		next := Definition{c.ID, c.Format, "udp", netip.MustParseAddrPort(c.Listen).String()}
		if exists {
			for k, i := range result {
				if i.ID == c.ID {
					result[k] = next
					break
				}
			}
		} else {
			result = append(result, next)
		}
	}
	if len(result) > 8 {
		return nil, ErrInvalid
	}
	for k, i := range result {
		for _, j := range result[:k] {
			if i.ID == j.ID || Overlap(i, j) {
				return nil, ErrInvalid
			}
		}
	}
	return result, nil
}
func Match(inputs []Control, status []Input) error {
	if ValidateControls(inputs) != nil {
		return ErrInvalid
	}
	for _, c := range inputs {
		if c.Format != "" || c.Listen != "" || c.Removed {
			return ErrInvalid
		}
	}
	_, e := Resolve(inputs, Definitions(status))
	return e
}
func MatchStatus(inputs []Control, status Status) error {
	for _, c := range inputs {
		if c.Format == "sflow5" && status.SFlowVersion != 1 {
			return ErrInvalid
		}
	}
	if status.InputManagement != 1 {
		return Match(inputs, status.Inputs)
	}
	_, e := Resolve(inputs, status.BaseInputs)
	return e
}
func ValidCode(s string) bool {
	switch s {
	case "", "invalid_packet", "peer_denied", "input_paused", "message_too_large", "missing_template", "stale_packet", "decoder_limit", "spool_full", "spool_error", "framing_error", "connection_limit", "source_read_failed", "listener_unavailable":
		return true
	}
	return false
}
func (s Status) Validate() error {
	if s.SFlowVersion < 0 || s.SFlowVersion > 1 {
		return ErrInvalid
	}
	if s.MonitoringVersion < 0 || s.MonitoringVersion > 1 || len(s.Watches) > 32 || s.MonitoringVersion == 0 && len(s.Watches) > 0 {
		return ErrInvalid
	}
	watchKeys := map[string]bool{}
	for _, w := range s.Watches {
		c := DefaultMonitor()
		c.Watches = []Watch{{Input: w.Input, Peer: w.Peer, SilenceSeconds: 180}}
		key := WatchKey(w.Input, w.Peer)
		if c.Validate() != nil || watchKeys[key] || w.Since.IsZero() || w.Since.Before(s.StartedAt) || w.Since.After(s.ObservedAt) || w.LastSeen != nil && (w.LastSeen.Before(w.Since) || w.LastSeen.After(s.ObservedAt)) {
			return ErrInvalid
		}
		watchKeys[key] = true
	}

	if s.StartedAt.IsZero() || s.ObservedAt.IsZero() || s.StartedAt.After(s.ObservedAt) || s.SampleSeconds < 0 || s.SampleSeconds > 86400*365 || s.AppliedRevision < 0 || len(s.Inputs) > 8 {
		return ErrInvalid
	}
	if s.ConfigError != "" && s.ConfigError != "policy_invalid" && s.ConfigError != "policy_persist_failed" && s.ConfigError != "policy_bind_failed" {
		return ErrInvalid
	}
	if s.InputManagement < 0 || s.InputManagement > 1 || len(s.BaseInputs) > 8 || s.InputManagement == 0 && len(s.BaseInputs) > 0 || s.ConfigErrorInput != "" && !telemetry.AgentIdentifier(s.ConfigErrorInput) {
		return ErrInvalid
	}
	baseIDs := map[string]bool{}
	for _, i := range s.BaseInputs {
		if !telemetry.AgentIdentifier(i.ID) || baseIDs[i.ID] {
			return ErrInvalid
		}
		baseIDs[i.ID] = true
		switch i.Format {
		case "netflow5", "netflow9", "ipfix", "sflow5", "syslog", "cef-firewall", "cef-fess", "suricata":
		default:
			return ErrInvalid
		}
		if i.Protocol == "file" {
			if i.Format != "suricata" || i.Listen != "" {
				return ErrInvalid
			}
		} else {
			if i.Protocol != "udp" && i.Protocol != "tcp" && i.Protocol != "tls" {
				return ErrInvalid
			}
			if !ValidListen(i.Listen) {
				return ErrInvalid
			}
		}
		if Flow(i.Format) && i.Protocol != "udp" {
			return ErrInvalid
		}
	}
	seen := map[string]bool{}
	for _, i := range s.Inputs {
		if !telemetry.AgentIdentifier(i.ID) || seen[i.ID] || len(i.Exporters) > 8 || !ValidCode(i.LastError) {
			return ErrInvalid
		}
		seen[i.ID] = true
		switch i.Format {
		case "syslog", "cef-firewall", "cef-fess", "suricata", "netflow5", "netflow9", "ipfix", "sflow5":
		default:
			return ErrInvalid
		}
		if i.Protocol == "file" {
			if i.Format != "suricata" || i.Listen != "" {
				return ErrInvalid
			}
		} else {
			if i.Protocol != "tcp" && i.Protocol != "tls" && i.Protocol != "udp" {
				return ErrInvalid
			}
			a, e := netip.ParseAddrPort(i.Listen)
			if e != nil || a.Port() == 0 || a.Addr().Zone() != "" || !ValidAllow(i.Allow) {
				return ErrInvalid
			}
		}
		if Flow(i.Format) && i.Protocol != "udp" {
			return ErrInvalid
		}
		if i.TemplateTTLSeconds != 0 && (i.Format != "netflow9" && i.Format != "ipfix" || i.TemplateTTLSeconds < 60 || i.TemplateTTLSeconds > 86400) {
			return ErrInvalid
		}
		switch i.State {
		case "listening", "receiving", "error", "paused", "not_attempted":
		default:
			return ErrInvalid
		}
		if i.LastError == "" && i.LastErrorAt != nil || i.LastError != "" && (i.LastErrorAt == nil || i.LastErrorAt.IsZero()) || i.LastMessageAt != nil && i.LastMessageAt.IsZero() {
			return ErrInvalid
		}
		peers := map[string]bool{}
		for _, p := range i.Exporters {
			a, e := netip.ParseAddr(p.Peer)
			key := netip.AddrPortFrom(a, p.Port).String() + "/" + strconv.FormatUint(uint64(p.Domain), 10)
			if e != nil || a.Zone() != "" || p.LastSeen.IsZero() || peers[key] {
				return ErrInvalid
			}
			peers[key] = true
		}
	}
	return nil
}
func (s Status) Key() string {
	parts := []string{s.ConfigError}
	for _, i := range s.Inputs {
		parts = append(parts, i.ID+":"+i.State)
	}
	return strings.Join(parts, ":")
}
