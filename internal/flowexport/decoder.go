// SPDX-License-Identifier: Apache-2.0
// Package flowexport decodes bounded NetFlow v9/IPFIX UDP exports. It has no
// delivery, database or identity dependencies. Evidence is self-contained so
// archived records never depend on mutable collector templates.
package flowexport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"
)

const (
	MaxPacket    = 12000
	MaxRecord    = 8192
	MaxFields    = 64
	MaxRecords   = 100
	MaxSessions  = 64
	MaxTemplates = 64
	DefaultTTL   = 15 * time.Minute
)

var (
	ErrInvalid = errors.New("invalid flow export")
	ErrLimit   = errors.New("flow export resource limit")
	ErrStale   = errors.New("stale or reordered flow export")
)

type Evidence struct {
	Header      []byte `json:"header"`
	TemplateSet uint16 `json:"template_set"`
	Template    []byte `json:"template"`
	Record      []byte `json:"record"`
	Ordinal     int    `json:"ordinal"`
}
type Header struct {
	Version                  uint16
	Domain, Sequence, Uptime uint32
	Exported                 time.Time
	Size                     int
}
type field struct {
	id, size   uint16
	enterprise bool
	pen        uint32
}
type template struct {
	id, set   uint16
	fields    []field
	scope     int
	raw       []byte
	min       int
	refreshed time.Time
}
type scope struct {
	input   string
	peer    netip.AddrPort
	version uint16
	domain  uint32
}
type session struct {
	header        Header
	seen, expires time.Time
	templates     map[uint16]template
}
type Decoder struct {
	mu       sync.Mutex
	sessions map[scope]session
}
type Result struct {
	Records                                    []Evidence
	UnknownSets, Templates, IgnoredWithdrawals int
	Reset                                      bool
}

func header(p []byte, whole bool) (Header, error) {
	var h Header
	if len(p) < 16 {
		return h, ErrInvalid
	}
	h.Version = binary.BigEndian.Uint16(p)
	u32 := binary.BigEndian.Uint32
	switch h.Version {
	case 9:
		if len(p) < 20 || binary.BigEndian.Uint16(p[2:]) == 0 {
			return h, ErrInvalid
		}
		h.Size = 20
		h.Uptime = u32(p[4:])
		h.Exported = time.Unix(int64(u32(p[8:])), 0).UTC()
		h.Sequence = u32(p[12:])
		h.Domain = u32(p[16:])
	case 10:
		h.Size = 16
		n := int(binary.BigEndian.Uint16(p[2:]))
		if n < 16 || n > MaxPacket || whole && n != len(p) {
			return h, ErrInvalid
		}
		h.Exported = time.Unix(int64(u32(p[4:])), 0).UTC()
		h.Sequence = u32(p[8:])
		h.Domain = u32(p[12:])
	default:
		return h, ErrInvalid
	}
	if h.Exported.Year() < 2000 || !whole && len(p) != h.Size {
		return h, ErrInvalid
	}
	return h, nil
}

func parseTemplate(version, set uint16, p []byte) (template, int, error) {
	t := template{set: set}
	if len(p) < 4 {
		return t, 0, ErrInvalid
	}
	t.id = binary.BigEndian.Uint16(p)
	count := int(binary.BigEndian.Uint16(p[2:]))
	pos := 4
	options := version == 9 && set == 1 || version == 10 && set == 3
	if count == 0 { // UDP withdrawals are ignored; return their actual wire length.
		if version != 10 {
			return t, 0, ErrInvalid
		}
		if t.id < 256 && t.id != set {
			return t, 0, ErrInvalid
		}
		return t, 4, nil
	}
	if t.id < 256 {
		return t, 0, ErrInvalid
	}
	if options {
		if len(p) < 6 {
			return t, 0, ErrInvalid
		}
		pos = 6
		if version == 9 {
			scopeBytes := count
			optionBytes := int(binary.BigEndian.Uint16(p[4:]))
			if scopeBytes%4 != 0 || optionBytes%4 != 0 {
				return t, 0, ErrInvalid
			}
			t.scope = scopeBytes / 4
			count = (scopeBytes + optionBytes) / 4
		} else {
			t.scope = int(binary.BigEndian.Uint16(p[4:]))
		}
		if t.scope == 0 || t.scope > count {
			return t, 0, ErrInvalid
		}
	}
	if count < 1 || count > MaxFields {
		return t, 0, ErrLimit
	}
	for j := 0; j < count; j++ {
		if len(p)-pos < 4 {
			return t, 0, ErrInvalid
		}
		f := field{id: binary.BigEndian.Uint16(p[pos:]), size: binary.BigEndian.Uint16(p[pos+2:])}
		pos += 4
		if version == 10 && f.id&0x8000 != 0 {
			f.enterprise = true
			f.id &= 0x7fff
			if len(p)-pos < 4 {
				return t, 0, ErrInvalid
			}
			f.pen = binary.BigEndian.Uint32(p[pos:])
			pos += 4
		}
		if f.size == 0 {
			return t, 0, ErrInvalid
		}
		if f.size == 65535 {
			if version != 10 {
				return t, 0, ErrInvalid
			}
			t.min++
		} else {
			t.min += int(f.size)
		}
		if t.min > MaxRecord {
			return t, 0, ErrLimit
		}
		t.fields = append(t.fields, f)
	}
	t.raw = bytes.Clone(p[:pos])
	return t, pos, nil
}

func record(t template, p []byte) ([][]byte, int, error) {
	if len(t.fields) == 0 {
		return nil, 0, ErrInvalid
	}
	pos := 0
	values := make([][]byte, 0, len(t.fields))
	for _, f := range t.fields {
		n := int(f.size)
		if n == 65535 {
			if pos >= len(p) {
				return nil, 0, ErrInvalid
			}
			n = int(p[pos])
			pos++
			if n == 255 {
				if len(p)-pos < 2 {
					return nil, 0, ErrInvalid
				}
				n = int(binary.BigEndian.Uint16(p[pos:]))
				pos += 2
				if n < 255 {
					return nil, 0, ErrInvalid
				}
			}
		}
		if n > MaxRecord-pos || len(p)-pos < n {
			return nil, 0, ErrInvalid
		}
		values = append(values, p[pos:pos+n])
		pos += n
	}
	return values, pos, nil
}
func zero(p []byte) bool {
	for _, b := range p {
		if b != 0 {
			return false
		}
	}
	return true
}

// Decode uses receive-time TTL, not exporter time. Keys include listener, source
// IP and UDP port, wire version and observation domain/source ID. Cache changes
// commit only after the complete datagram passes structural validation.
func (d *Decoder) Decode(input string, peer netip.AddrPort, p []byte, now time.Time, ttl time.Duration) (out Result, err error) {
	if input == "" || !peer.IsValid() || peer.Port() == 0 || len(p) > MaxPacket || ttl < time.Minute || ttl > 24*time.Hour {
		return out, ErrInvalid
	}
	h, e := header(p, true)
	if e != nil {
		return out, e
	}
	if h.Exported.After(now.Add(5 * time.Minute)) {
		return out, ErrInvalid
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sessions == nil {
		d.sessions = map[scope]session{}
	}
	for k, s := range d.sessions {
		if !now.Before(s.expires) {
			delete(d.sessions, k)
		}
	}
	k := scope{input, netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port()), h.Version, h.Domain}
	old, exists := d.sessions[k]
	defer func() {
		if err != nil && !errors.Is(err, ErrStale) {
			delete(d.sessions, k)
		}
	}()
	if !exists && len(d.sessions) >= MaxSessions {
		return out, ErrLimit
	}
	s := session{header: h, seen: now, expires: now.Add(ttl), templates: map[uint16]template{}}
	if exists {
		// Older-clock UDP packets cannot replace a newer template. A clock step
		// backwards requires timeout/new session, rather than guessing a reboot.
		if h.Exported.Before(old.header.Exported) {
			return out, ErrStale
		}
		reset := false
		if h.Version == 9 && h.Uptime < old.header.Uptime {
			wrapped := uint64(h.Uptime - old.header.Uptime)
			elapsed := uint64(h.Exported.Sub(old.header.Exported) / time.Millisecond)
			reset = wrapped > elapsed+uint64((5*time.Minute)/time.Millisecond)
		}
		if int32(h.Sequence-old.header.Sequence) < 0 {
			if h.Exported.After(old.header.Exported) {
				reset = true
			} else if !reset {
				return out, ErrStale
			}
		}
		out.Reset = reset
		if !reset {
			for id, t := range old.templates {
				if now.Sub(t.refreshed) < ttl {
					s.templates[id] = t
				}
			}
		}
	}
	for pos := h.Size; pos < len(p); {
		if len(p)-pos < 4 {
			return Result{}, ErrInvalid
		}
		set := binary.BigEndian.Uint16(p[pos:])
		size := int(binary.BigEndian.Uint16(p[pos+2:]))
		if size < 4 || size > len(p)-pos {
			return Result{}, ErrInvalid
		}
		body := p[pos+4 : pos+size]
		pos += size
		isTemplate := h.Version == 9 && (set == 0 || set == 1) || h.Version == 10 && (set == 2 || set == 3)
		if isTemplate {
			for len(body) > 0 {
				paddingLimit := 3
				if set == 1 || set == 3 {
					paddingLimit = 5
				}
				if len(body) <= paddingLimit && zero(body) {
					break
				}
				t, n, e := parseTemplate(h.Version, set, body)
				if e != nil {
					return Result{}, e
				}
				body = body[n:]
				if len(t.fields) == 0 {
					out.IgnoredWithdrawals++
					continue
				}
				if _, ok := s.templates[t.id]; !ok && len(s.templates) >= MaxTemplates {
					return Result{}, ErrLimit
				}
				t.refreshed = now
				s.templates[t.id] = t
				out.Templates++
			}
		} else if set >= 256 {
			t, ok := s.templates[set]
			if !ok {
				out.UnknownSets++
				continue
			}
			for len(body) > 0 {
				// Padding must be zero and shorter than one minimum-size record.
				if len(body) < t.min {
					if h.Version == 9 && len(body) > 3 || !zero(body) {
						return Result{}, ErrInvalid
					}
					break
				}
				_, n, e := record(t, body)
				if e != nil {
					return Result{}, e
				}
				if len(out.Records) >= MaxRecords {
					return Result{}, ErrLimit
				}
				out.Records = append(out.Records, Evidence{Header: bytes.Clone(p[:h.Size]), TemplateSet: t.set, Template: bytes.Clone(t.raw), Record: bytes.Clone(body[:n]), Ordinal: len(out.Records)})
				body = body[n:]
			}
		} else {
			return Result{}, ErrInvalid
		}
	}
	d.sessions[k] = s
	return out, nil
}

// ForgetInput discards templates when admission/TTL controls change. Buffered
// evidence already contains its template and is unaffected.
func (d *Decoder) ForgetInput(input string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k := range d.sessions {
		if k.input == input {
			delete(d.sessions, k)
		}
	}
}
