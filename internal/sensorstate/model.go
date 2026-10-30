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
	ID                 string   `json:"id"`
	Enabled            bool     `json:"enabled"`
	Allow              []string `json:"allow"`
	TemplateTTLSeconds int      `json:"template_ttl_seconds"`
}
type Policy struct {
	Revision  int64     `json:"revision"`
	Inputs    []Control `json:"inputs"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}
type Change struct {
	AgentID          string    `json:"agent_id"`
	ExpectedRevision int64     `json:"expected_revision"`
	Inputs           []Control `json:"inputs"`
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
type Status struct {
	StartedAt       time.Time `json:"started_at"`
	ObservedAt      time.Time `json:"observed_at"`
	SampleSeconds   float64   `json:"sample_seconds"`
	AppliedRevision int64     `json:"applied_revision"`
	ConfigError     string    `json:"config_error,omitempty"`
	Inputs          []Input   `json:"inputs"`
}

func Flow(format string) bool {
	return format == "netflow5" || format == "netflow9" || format == "ipfix"
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
func ValidateControls(inputs []Control) error {
	if len(inputs) > 8 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, i := range inputs {
		if !telemetry.AgentIdentifier(i.ID) || seen[i.ID] || !ValidAllow(i.Allow) || i.TemplateTTLSeconds != 0 && (i.TemplateTTLSeconds < 60 || i.TemplateTTLSeconds > 86400) {
			return ErrInvalid
		}
		seen[i.ID] = true
	}
	return nil
}

// Controls may only address existing flow listeners; bind addresses, TLS keys,
// file paths and SIEM credentials remain under local operator control.
func Match(inputs []Control, status []Input) error {
	if e := ValidateControls(inputs); e != nil {
		return e
	}
	for _, c := range inputs {
		found := false
		for _, i := range status {
			if i.ID == c.ID {
				found = Flow(i.Format) && i.Protocol == "udp" && (i.Format != "netflow5" || c.TemplateTTLSeconds == 0)
				break
			}
		}
		if !found {
			return ErrInvalid
		}
	}
	return nil
}
func ValidCode(s string) bool {
	switch s {
	case "", "invalid_packet", "peer_denied", "input_paused", "message_too_large", "missing_template", "stale_packet", "decoder_limit", "spool_full", "spool_error", "framing_error", "connection_limit", "source_read_failed":
		return true
	}
	return false
}
func (s Status) Validate() error {
	if s.StartedAt.IsZero() || s.ObservedAt.IsZero() || s.StartedAt.After(s.ObservedAt) || s.SampleSeconds < 0 || s.SampleSeconds > 86400*365 || s.AppliedRevision < 0 || len(s.Inputs) < 1 || len(s.Inputs) > 8 {
		return ErrInvalid
	}
	if s.ConfigError != "" && s.ConfigError != "policy_invalid" && s.ConfigError != "policy_persist_failed" {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, i := range s.Inputs {
		if !telemetry.AgentIdentifier(i.ID) || seen[i.ID] || len(i.Exporters) > 8 || !ValidCode(i.LastError) {
			return ErrInvalid
		}
		seen[i.ID] = true
		switch i.Format {
		case "syslog", "cef-firewall", "cef-fess", "suricata", "netflow5", "netflow9", "ipfix":
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
