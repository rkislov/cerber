// SPDX-License-Identifier: Apache-2.0
package flowexport

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"time"
)

type Flow struct {
	Header                                                                               Header
	TemplateID                                                                           uint16
	TemplateHash                                                                         string
	Options                                                                              bool
	Source, Destination                                                                  string
	SourcePort, DestinationPort, Protocol, Input, Output, SamplingMode, SamplingInterval int
	Packets, Bytes                                                                       uint64
	Start, End                                                                           *time.Time
	TimeBasis                                                                            string
	ID                                                                                   string
}

// DecodeEvidence repeats the interpretation on the SIEM without a template
// cache. Unknown enterprise IEs and Options records are preserved, not guessed.
func DecodeEvidence(e Evidence) (Flow, error) {
	var out Flow
	h, err := header(e.Header, false)
	if err != nil {
		return out, err
	}
	if e.Ordinal < 0 || e.Ordinal >= MaxRecords || len(e.Record) > MaxRecord {
		return out, ErrInvalid
	}
	if h.Version == 9 && e.TemplateSet > 1 || h.Version == 10 && e.TemplateSet != 2 && e.TemplateSet != 3 {
		return out, ErrInvalid
	}
	t, n, err := parseTemplate(h.Version, e.TemplateSet, e.Template)
	if err != nil || n != len(e.Template) || len(t.fields) == 0 {
		return out, ErrInvalid
	}
	values, n, err := record(t, e.Record)
	if err != nil || n != len(e.Record) {
		return out, ErrInvalid
	}
	sum := sha256.Sum256(e.Template)
	out = Flow{Header: h, TemplateID: t.id, TemplateHash: hex.EncodeToString(sum[:]), Options: t.scope > 0, TimeBasis: "exporter_export_time", ID: fmt.Sprintf("%d:%d:%d:%d", h.Domain, h.Sequence, t.id, e.Ordinal)}
	if out.Options {
		return out, nil
	}
	fields := map[uint16][]byte{}
	for j, f := range t.fields {
		if f.enterprise || !knownField(f.id) {
			continue
		}
		if _, ok := fields[f.id]; ok {
			return out, ErrInvalid
		}
		fields[f.id] = values[j]
	}
	number := func(id uint16, max int) (uint64, error) {
		v, ok := fields[id]
		if !ok {
			return 0, nil
		}
		if len(v) < 1 || len(v) > max {
			return 0, ErrInvalid
		}
		var n uint64
		for _, b := range v {
			n = n<<8 | uint64(b)
		}
		return n, nil
	}
	ip := func(v4, v6 uint16) (string, error) {
		a, b := fields[v4], fields[v6]
		if a != nil && b != nil {
			return "", ErrInvalid
		}
		if a != nil {
			if len(a) != 4 {
				return "", ErrInvalid
			}
			return netip.AddrFrom4([4]byte(a)).String(), nil
		}
		if b != nil {
			if len(b) != 16 {
				return "", ErrInvalid
			}
			return netip.AddrFrom16([16]byte(b)).Unmap().String(), nil
		}
		return "", nil
	}
	if out.Source, err = ip(8, 27); err != nil {
		return out, err
	}
	if out.Destination, err = ip(12, 28); err != nil {
		return out, err
	}
	for _, v := range []struct {
		id     uint16
		max    int
		target *int
	}{{4, 1, &out.Protocol}, {7, 2, &out.SourcePort}, {11, 2, &out.DestinationPort}, {10, 4, &out.Input}, {14, 4, &out.Output}, {34, 4, &out.SamplingInterval}, {35, 1, &out.SamplingMode}} {
		n, e := number(v.id, v.max)
		if e != nil {
			return out, e
		}
		*v.target = int(n)
	}
	if out.Bytes, err = number(1, 8); err != nil {
		return out, err
	}
	if out.Packets, err = number(2, 8); err != nil {
		return out, err
	}
	// Each supported time representation must be paired and internally valid.
	// Contradictory clocks are rejected instead of silently choosing one.
	setTime := func(start, end time.Time, basis string) error {
		if start.Year() < 2000 || end.Before(start) || end.After(h.Exported.Add(5*time.Second)) || end.Sub(start) > 24*time.Hour {
			return ErrInvalid
		}
		if out.Start != nil && (abs(start.Sub(*out.Start)) > time.Second || abs(end.Sub(*out.End)) > time.Second) {
			return ErrInvalid
		}
		start = start.UTC()
		end = end.UTC()
		out.Start = &start
		out.End = &end
		out.TimeBasis = basis
		return nil
	}
	if h.Version == 10 {
		for _, pair := range []struct {
			start, end uint16
			size       int
			unit       time.Duration
		}{{150, 151, 4, time.Second}, {152, 153, 8, time.Millisecond}, {158, 159, 4, time.Microsecond}} {
			a, aok := fields[pair.start]
			b, bok := fields[pair.end]
			if !aok && !bok {
				continue
			}
			if aok && len(a) != pair.size || bok && len(b) != pair.size {
				return out, ErrInvalid
			}
			if !aok || !bok {
				continue
			}
			x, _ := number(pair.start, pair.size)
			y, _ := number(pair.end, pair.size)
			var st, en time.Time
			if pair.start == 158 {
				st = h.Exported.Add(-time.Duration(x) * time.Microsecond)
				en = h.Exported.Add(-time.Duration(y) * time.Microsecond)
			} else {
				// Limit absolute counters before converting to signed nanoseconds.
				factor := uint64(time.Second / pair.unit)
				if x > 4102444800*factor || y > 4102444800*factor {
					return out, ErrInvalid
				}
				st = time.Unix(int64(x/factor), int64(x%factor)*int64(pair.unit))
				en = time.Unix(int64(y/factor), int64(y%factor)*int64(pair.unit))
			}
			if err = setTime(st, en, "exporter_absolute_clock"); err != nil {
				return out, err
			}
		}
		for _, pair := range [][2]uint16{{154, 155}, {156, 157}} {
			a, aok := fields[pair[0]]
			b, bok := fields[pair[1]]
			if !aok && !bok {
				continue
			}
			if aok && len(a) != 8 || bok && len(b) != 8 {
				return out, ErrInvalid
			}
			if !aok || !bok {
				continue
			}
			x, _ := number(pair[0], 8)
			y, _ := number(pair[1], 8)
			ntp := func(v uint64) time.Time {
				sec, frac := int64(v>>32), v&0xffffffff
				if pair[0] == 154 {
					frac &= ^uint64(2047)
				}
				era := (h.Exported.Unix() + 2208988800) >> 32
				best := time.Unix((era<<32)+sec-2208988800, int64((frac*1000000000)>>32))
				for _, delta := range []int64{-1, 1} {
					candidate := time.Unix(((era+delta)<<32)+sec-2208988800, int64((frac*1000000000)>>32))
					if abs(candidate.Sub(h.Exported)) < abs(best.Sub(h.Exported)) {
						best = candidate
					}
				}
				return best
			}
			if err = setTime(ntp(x), ntp(y), "exporter_absolute_clock"); err != nil {
				return out, err
			}
		}
	}
	a, aok := fields[22]
	b, bok := fields[21]
	if aok || bok {
		if aok && len(a) != 4 || bok && len(b) != 4 {
			return out, ErrInvalid
		}
		if !aok || !bok {
			return out, nil
		}
		start, _ := number(22, 4)
		end, _ := number(21, 4)
		if h.Version == 9 {
			sa, ea := h.Uptime-uint32(start), h.Uptime-uint32(end)
			if sa > uint32((24*time.Hour)/time.Millisecond) || ea > sa {
				return out, ErrInvalid
			}
			if err = setTime(h.Exported.Add(-time.Duration(sa)*time.Millisecond), h.Exported.Add(-time.Duration(ea)*time.Millisecond), "exporter_uptime_and_clock"); err != nil {
				return out, err
			}
		} else if boot, ok := fields[160]; ok {
			if len(boot) != 8 {
				return out, ErrInvalid
			}
			ms, _ := number(160, 8)
			if ms > 4102444800000 {
				return out, ErrInvalid
			}
			base := time.UnixMilli(int64(ms))
			uptime := h.Exported.Sub(base) / time.Millisecond
			// No guessing the 49-day wrap epoch from a boot time alone.
			if uptime < 0 || uptime > 0xffffffff || end < start {
				return out, ErrInvalid
			}
			if err = setTime(base.Add(time.Duration(start)*time.Millisecond), base.Add(time.Duration(end)*time.Millisecond), "exporter_uptime_and_clock"); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}
func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func knownField(id uint16) bool {
	switch id {
	case 1, 2, 4, 7, 8, 10, 11, 12, 14, 21, 22, 27, 28, 34, 35, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160:
		return true
	}
	return false
}
