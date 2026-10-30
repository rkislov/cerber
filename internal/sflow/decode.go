// SPDX-License-Identifier: Apache-2.0
// Package sflow decodes bounded sFlow v5 packet samples. No counters are extrapolated.
// Wire reference: https://sflow.org/sflow_version_5.txt
package sflow

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var ErrInvalid = errors.New("invalid sFlow v5 datagram")

type Sample struct {
	Agent, Source, Destination                                          string
	SubAgent, Sequence, Uptime, SampleSequence, SourceType, SourceIndex uint32
	Rate, Pool, Drops, InputFormat, Input, OutputFormat, Output, Length uint32
	Protocol, SourcePort, DestinationPort                               int
}
type reader struct {
	p   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if n < 0 || n > len(r.p) {
		r.bad = true
		return nil
	}
	p := r.p[:n]
	r.p = r.p[n:]
	return p
}
func (r *reader) u() uint32 {
	p := r.take(4)
	if len(p) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(p)
}
func (r *reader) blob() []byte {
	n := r.u()
	if n > 12000 {
		r.bad = true
		return nil
	}
	p := r.take(int(n))
	r.take(int((4 - n%4) % 4))
	return p
}
func addr(p []byte) string {
	a, ok := netip.AddrFromSlice(p)
	if !ok {
		return ""
	}
	return a.Unmap().String()
}

// Decode preserves sample order (including metadata-only samples) for replay of raw evidence.
func Decode(p []byte) ([]Sample, error) {
	if len(p) > 12000 {
		return nil, ErrInvalid
	}
	r := reader{p: p}
	if r.u() != 5 {
		return nil, ErrInvalid
	}
	var agent string
	switch r.u() {
	case 1:
		agent = addr(r.take(4))
	case 2:
		agent = addr(r.take(16))
	default:
		return nil, ErrInvalid
	}
	base := Sample{Agent: agent, SubAgent: r.u(), Sequence: r.u(), Uptime: r.u()}
	n := r.u()
	if n > 100 {
		return nil, ErrInvalid
	}
	out := make([]Sample, 0, n)
	for k := uint32(0); k < n; k++ {
		format := r.u()
		data := r.blob()
		s := base
		if format == 1 || format == 3 {
			b := reader{p: data}
			s.SampleSequence = b.u()
			id := b.u()
			s.SourceType = id >> 24
			s.SourceIndex = id & 0xffffff
			if format == 3 {
				s.SourceType = id
				s.SourceIndex = b.u()
			}
			s.Rate = b.u()
			s.Pool = b.u()
			s.Drops = b.u()
			s.Input = b.u()
			if format == 3 {
				s.InputFormat = s.Input
				s.Input = b.u()
			} else {
				s.InputFormat = s.Input >> 30
				s.Input &= 0x3fffffff
			}
			s.Output = b.u()
			if format == 3 {
				s.OutputFormat = s.Output
				s.Output = b.u()
			} else {
				s.OutputFormat = s.Output >> 30
				s.Output &= 0x3fffffff
			}
			count := b.u()
			if count > 100 {
				return nil, ErrInvalid
			}
			found := false
			for j := uint32(0); j < count; j++ {
				kind := b.u()
				record := b.blob()
				v := Sample{}
				ok, e := packet(kind, record, &v)
				if e != nil {
					return nil, e
				}
				if ok && !found {
					s.Source = v.Source
					s.Destination = v.Destination
					s.Protocol = v.Protocol
					s.SourcePort = v.SourcePort
					s.DestinationPort = v.DestinationPort
					s.Length = v.Length
					found = true
				}
			}
			if b.bad {
				return nil, ErrInvalid
			}
		}
		out = append(out, s)
	}
	if r.bad || len(r.p) != 0 || agent == "" {
		return nil, ErrInvalid
	}
	return out, nil
}
func packet(kind uint32, p []byte, s *Sample) (bool, error) {
	r := reader{p: p}
	switch kind {
	case 3, 4:
		s.Length = r.u()
		s.Protocol = int(r.u())
		n := 4
		if kind == 4 {
			n = 16
		}
		s.Source = addr(r.take(n))
		s.Destination = addr(r.take(n))
		s.SourcePort = int(r.u())
		s.DestinationPort = int(r.u())
		r.u()
		r.u()
		if r.bad || s.Protocol > 255 || s.SourcePort > 65535 || s.DestinationPort > 65535 {
			return false, ErrInvalid
		}
		return true, nil
	case 1:
		protocol := r.u()
		s.Length = r.u()
		r.u()
		header := r.blob()
		if r.bad {
			return false, ErrInvalid
		}
		if protocol == 1 {
			if len(header) < 14 {
				return false, nil
			}
			typ := binary.BigEndian.Uint16(header[12:14])
			header = header[14:]
			for k := 0; k < 2 && (typ == 0x8100 || typ == 0x88a8); k++ {
				if len(header) < 4 {
					return false, nil
				}
				typ = binary.BigEndian.Uint16(header[2:4])
				header = header[4:]
			}
			switch typ {
			case 0x0800:
				protocol = 11
			case 0x86dd:
				protocol = 12
			default:
				return false, nil
			}
		}
		return ipHeader(protocol, header, s), nil
	default:
		return false, nil
	}
}
func ipHeader(protocol uint32, p []byte, s *Sample) bool {
	offset := 0
	fragment := false
	switch protocol {
	case 11:
		if len(p) < 20 || p[0]>>4 != 4 {
			return false
		}
		offset = int(p[0]&15) * 4
		if offset < 20 || offset > len(p) || int(binary.BigEndian.Uint16(p[2:4])) < offset {
			return false
		}
		if total := int(binary.BigEndian.Uint16(p[2:4])); total < len(p) {
			p = p[:total]
		}
		s.Source = addr(p[12:16])
		s.Destination = addr(p[16:20])
		s.Protocol = int(p[9])
		fragment = binary.BigEndian.Uint16(p[6:8])&0x1fff != 0
	case 12:
		if len(p) < 40 || p[0]>>4 != 6 {
			return false
		}
		if total := 40 + int(binary.BigEndian.Uint16(p[4:6])); total < len(p) {
			p = p[:total]
		}
		s.Source = addr(p[8:24])
		s.Destination = addr(p[24:40])
		s.Protocol = int(p[6])
		offset = 40
		for k := 0; k < 8; k++ {
			next := s.Protocol
			if next != 0 && next != 43 && next != 60 && next != 44 && next != 51 {
				break
			}
			if offset+2 > len(p) {
				return true
			}
			size := (int(p[offset+1]) + 1) * 8
			if next == 44 {
				size = 8
				if offset+8 > len(p) {
					return true
				}
				fragment = binary.BigEndian.Uint16(p[offset+2:offset+4])&0xfff8 != 0
			}
			if next == 51 {
				size = (int(p[offset+1]) + 2) * 4
			}
			if offset+size > len(p) {
				return true
			}
			s.Protocol = int(p[offset])
			offset += size
			if fragment {
				break
			}
		}
	default:
		return false
	}
	if !fragment && (s.Protocol == 6 || s.Protocol == 17) && offset+4 <= len(p) {
		s.SourcePort = int(binary.BigEndian.Uint16(p[offset : offset+2]))
		s.DestinationPort = int(binary.BigEndian.Uint16(p[offset+2 : offset+4]))
	}
	return true
}
