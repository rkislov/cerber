// SPDX-License-Identifier: Apache-2.0
package flowexport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"
)

var fixtureTime = time.Date(2026, 10, 30, 8, 0, 0, 0, time.UTC)
var fixturePeer = netip.MustParseAddrPort("192.0.2.254:50000")

func words(v ...uint16) []byte {
	p := make([]byte, 2*len(v))
	for i, x := range v {
		binary.BigEndian.PutUint16(p[2*i:], x)
	}
	return p
}
func uints(v ...uint32) []byte {
	p := make([]byte, 4*len(v))
	for i, x := range v {
		binary.BigEndian.PutUint32(p[4*i:], x)
	}
	return p
}
func long(v uint64) []byte           { p := make([]byte, 8); binary.BigEndian.PutUint64(p, v); return p }
func set(id uint16, p []byte) []byte { return append(words(id, uint16(len(p)+4)), p...) }
func packet(version uint16, seq, domain uint32, at time.Time, sets ...[]byte) []byte {
	var p []byte
	if version == 9 {
		p = append(words(9, 1), uints(10000, uint32(at.Unix()), seq, domain)...)
	} else {
		p = append(words(10, 0), uints(uint32(at.Unix()), seq, domain)...)
	}
	for _, s := range sets {
		p = append(p, s...)
	}
	if version == 10 {
		binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	}
	return p
}
func fixture(version uint16) ([]byte, []byte) {
	t := words(256, 7, 8, 4, 12, 4, 7, 2, 11, 2, 4, 1)
	d := append([]byte{192, 0, 2, 1, 192, 0, 2, 2}, words(12345, 445)...)
	d = append(d, 6)
	if version == 9 {
		t = append(t, words(22, 4, 21, 4)...)
		d = append(d, uints(8000, 9000)...)
	} else {
		t = append(t, words(152, 8, 153, 8)...)
		d = append(d, long(uint64(fixtureTime.Add(-2*time.Second).UnixMilli()))...)
		d = append(d, long(uint64(fixtureTime.Add(-time.Second).UnixMilli()))...)
	}
	return t, d
}
func templateSet(v uint16) uint16 {
	if v == 9 {
		return 0
	}
	return 2
}

func TestTemplatesAndEvidenceRemainIndependent(t *testing.T) {
	for _, version := range []uint16{9, 10} {
		var dec Decoder
		tmpl, data := fixture(version)
		first, e := dec.Decode("flows", fixturePeer, packet(version, 10, 42, fixtureTime, set(templateSet(version), tmpl)), fixtureTime, DefaultTTL)
		if e != nil || first.Templates != 1 || len(first.Records) != 0 {
			t.Fatal(first, e)
		}
		r, e := dec.Decode("flows", fixturePeer, packet(version, 11, 42, fixtureTime, set(256, data)), fixtureTime, DefaultTTL)
		if e != nil || len(r.Records) != 1 {
			t.Fatal(r, e)
		}
		f, e := DecodeEvidence(r.Records[0])
		if e != nil || f.Source != "192.0.2.1" || f.DestinationPort != 445 || f.Protocol != 6 || f.Header.Domain != 42 || f.TemplateID != 256 || f.Start == nil || f.End.Sub(*f.Start) != time.Second {
			t.Fatal(f, e)
		}
		// Reuse the same ID with reordered equal-width address fields.
		changed := bytes.Clone(tmpl)
		binary.BigEndian.PutUint16(changed[4:], 12)
		binary.BigEndian.PutUint16(changed[8:], 8)
		newer, e := dec.Decode("flows", fixturePeer, packet(version, 12, 42, fixtureTime.Add(time.Second), set(templateSet(version), changed), set(256, data)), fixtureTime.Add(time.Second), DefaultTTL)
		if e != nil {
			t.Fatal(e)
		}
		nf, e := DecodeEvidence(newer.Records[0])
		if e != nil || nf.Source != "192.0.2.2" || nf.TemplateHash == f.TemplateHash {
			t.Fatal(nf, e)
		}
		old, e := DecodeEvidence(r.Records[0])
		if e != nil || old.Source != f.Source || old.TemplateHash != f.TemplateHash {
			t.Fatal("snapshot changed", old, e)
		}
	}
}

func TestTemplateScopesExpiryRestartAndReorder(t *testing.T) {
	for _, version := range []uint16{9, 10} {
		var dec Decoder
		tmpl, data := fixture(version)
		learn := packet(version, 100, 42, fixtureTime, set(templateSet(version), tmpl))
		if _, e := dec.Decode("a", fixturePeer, learn, fixtureTime, time.Minute); e != nil {
			t.Fatal(e)
		}
		for _, v := range []struct {
			input  string
			peer   netip.AddrPort
			domain uint32
		}{{"b", fixturePeer, 42}, {"a", netip.MustParseAddrPort("192.0.2.253:50000"), 42}, {"a", netip.MustParseAddrPort("192.0.2.254:50001"), 42}, {"a", fixturePeer, 43}} {
			r, e := dec.Decode(v.input, v.peer, packet(version, 101, v.domain, fixtureTime, set(256, data)), fixtureTime, time.Minute)
			if e != nil || r.UnknownSets != 1 || len(r.Records) != 0 {
				t.Fatal("scope bypass", v, r, e)
			}
		}
		if _, e := dec.Decode("a", fixturePeer, packet(version, 99, 42, fixtureTime, set(templateSet(version), tmpl)), fixtureTime, time.Minute); !errors.Is(e, ErrStale) {
			t.Fatal("stale template accepted", e)
		}
		r, e := dec.Decode("a", fixturePeer, packet(version, 101, 42, fixtureTime, set(256, data)), fixtureTime, time.Minute)
		if e != nil || len(r.Records) != 1 {
			t.Fatal("stale packet destroyed good state", r, e)
		}
		r, e = dec.Decode("a", fixturePeer, packet(version, 1, 42, fixtureTime.Add(time.Second), set(256, data)), fixtureTime.Add(time.Second), time.Minute)
		if e != nil || !r.Reset || r.UnknownSets != 1 {
			t.Fatal("restarted sequence reused template", r, e)
		}
		dec.Decode("a", fixturePeer, packet(version, 2, 42, fixtureTime.Add(time.Second), set(templateSet(version), tmpl)), fixtureTime.Add(time.Second), time.Minute)
		// Data messages do not refresh template lifetime.
		dec.Decode("a", fixturePeer, packet(version, 3, 42, fixtureTime.Add(30*time.Second), set(256, data)), fixtureTime.Add(30*time.Second), time.Minute)
		r, e = dec.Decode("a", fixturePeer, packet(version, 4, 42, fixtureTime.Add(62*time.Second), set(256, data)), fixtureTime.Add(62*time.Second), time.Minute)
		if e != nil || r.UnknownSets != 1 {
			t.Fatal("template did not expire", r, e)
		}
	}
}

func TestIPFIXEnterpriseVariableOptionsAndUDPWithdrawal(t *testing.T) {
	var d Decoder
	tmpl, data := fixture(10)
	binary.BigEndian.PutUint16(tmpl[2:], 8)
	// Enterprise IE 8 must not replace the standard sourceIPv4Address.
	tmpl = append(tmpl, words(0x8008, 65535)...)
	tmpl = append(tmpl, uints(32473)...)
	data = append(data, 3, 'f', 'o', 'o')
	r, e := d.Decode("x", fixturePeer, packet(10, 1, 0, fixtureTime, set(2, tmpl), set(256, data)), fixtureTime, DefaultTTL)
	if e != nil {
		t.Fatal(e)
	}
	f, e := DecodeEvidence(r.Records[0])
	if e != nil || f.Source != "192.0.2.1" {
		t.Fatal(f, e)
	}
	r, e = d.Decode("x", fixturePeer, packet(10, 2, 0, fixtureTime, set(2, words(256, 0)), set(256, data)), fixtureTime, DefaultTTL)
	if e != nil || r.IgnoredWithdrawals != 1 || len(r.Records) != 1 {
		t.Fatal("UDP withdrawal was applied", r, e)
	}
	options := words(257, 2, 1, 8, 4, 34, 4)
	r, e = d.Decode("x", fixturePeer, packet(10, 3, 0, fixtureTime, set(3, options), set(257, uints(0xc0000201, 100))), fixtureTime, DefaultTTL)
	if e != nil {
		t.Fatal(e)
	}
	f, e = DecodeEvidence(r.Records[0])
	if e != nil || !f.Options || f.Source != "" || f.SamplingInterval != 0 {
		t.Fatal("option scope treated as source IP", f, e)
	}
}

func TestV9OptionsAndUptimeWrap(t *testing.T) {
	var d Decoder
	r, e := d.Decode("x", fixturePeer, packet(9, 1, 1, fixtureTime, set(1, words(257, 4, 4, 1, 4, 34, 4)), set(257, uints(1, 100))), fixtureTime, DefaultTTL)
	if e != nil {
		t.Fatal(e)
	}
	f, e := DecodeEvidence(r.Records[0])
	if e != nil || !f.Options || f.Source != "" {
		t.Fatal(f, e)
	}
	tmpl, data := fixture(9)
	p := packet(9, 0xfffffffe, 2, fixtureTime, set(0, tmpl))
	binary.BigEndian.PutUint32(p[4:], 0xfffffff0)
	d.Decode("x", fixturePeer, p, fixtureTime, DefaultTTL)
	p = packet(9, 1, 2, fixtureTime.Add(time.Second), set(256, data))
	binary.BigEndian.PutUint32(p[4:], 10000)
	r, e = d.Decode("x", fixturePeer, p, fixtureTime.Add(time.Second), DefaultTTL)
	if e != nil || r.Reset || len(r.Records) != 1 {
		t.Fatal("natural wrap reset templates", r, e)
	}
	p = packet(9, 2, 2, fixtureTime.Add(2*time.Second), set(256, data))
	binary.BigEndian.PutUint32(p[4:], 100)
	r, e = d.Decode("x", fixturePeer, p, fixtureTime.Add(2*time.Second), DefaultTTL)
	if e != nil || !r.Reset || r.UnknownSets != 1 {
		t.Fatal("uptime reset ignored", r, e)
	}
}

func TestMalformedDatagramInvalidatesCacheAndBounds(t *testing.T) {
	var d Decoder
	tmpl, data := fixture(10)
	valid := packet(10, 1, 1, fixtureTime, set(2, tmpl), set(256, data))
	for cut := 0; cut < len(valid); cut++ {
		var fresh Decoder
		p := bytes.Clone(valid[:cut])
		if len(p) >= 4 {
			binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
		}
		r, e := fresh.Decode("x", fixturePeer, p, fixtureTime, DefaultTTL)
		if e == nil {
			for _, ev := range r.Records {
				if _, e := DecodeEvidence(ev); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
	d.Decode("x", fixturePeer, valid, fixtureTime, DefaultTTL)
	broken := packet(10, 2, 1, fixtureTime, set(256, append(bytes.Clone(data), 1)))
	if _, e := d.Decode("x", fixturePeer, broken, fixtureTime, DefaultTTL); e == nil {
		t.Fatal("nonzero padding accepted")
	}
	r, e := d.Decode("x", fixturePeer, packet(10, 3, 1, fixtureTime, set(256, data)), fixtureTime, DefaultTTL)
	if e != nil || r.UnknownSets != 1 {
		t.Fatal("malformed session continued with stale cache", r, e)
	}
	for n := uint32(0); n < MaxSessions; n++ {
		if _, e = d.Decode("bounded", fixturePeer, packet(10, 1, n, fixtureTime, set(2, tmpl)), fixtureTime, DefaultTTL); n < MaxSessions-1 && e != nil {
			t.Fatal(e)
		}
	}
	if _, e = d.Decode("bounded", fixturePeer, packet(10, 1, 1000, fixtureTime, set(2, tmpl)), fixtureTime, DefaultTTL); !errors.Is(e, ErrLimit) {
		t.Fatal("unbounded sessions", e)
	}
}

func TestIPv6ReducedCountersAndNTP(t *testing.T) {
	var d Decoder
	tmpl := words(256, 9, 27, 16, 28, 16, 7, 2, 11, 2, 4, 1, 1, 3, 2, 1, 156, 8, 157, 8)
	src := netip.MustParseAddr("2001:db8::1").As16()
	dst := netip.MustParseAddr("2001:db8::2").As16()
	data := append(src[:], dst[:]...)
	data = append(data, words(12345, 443)...)
	data = append(data, 6, 0, 1, 0, 2)
	ntp := func(at time.Time) uint64 {
		return uint64(uint32(at.Unix()+2208988800))<<32 | uint64(at.Nanosecond())*(1<<32)/1e9
	}
	data = append(data, long(ntp(fixtureTime.Add(-2*time.Second)))...)
	data = append(data, long(ntp(fixtureTime.Add(-time.Second)))...)
	r, e := d.Decode("v6", fixturePeer, packet(10, 1, 0, fixtureTime, set(2, tmpl), set(256, data)), fixtureTime, DefaultTTL)
	if e != nil {
		t.Fatal(e)
	}
	f, e := DecodeEvidence(r.Records[0])
	if e != nil || f.Source != "2001:db8::1" || f.Bytes != 256 || f.Packets != 2 || f.Start == nil || !f.End.Equal(fixtureTime.Add(-time.Second)) {
		t.Fatal(f, e)
	}
}

func FuzzDecode(f *testing.F) {
	for _, v := range []uint16{9, 10} {
		tmpl, data := fixture(v)
		f.Add(packet(v, 1, 1, fixtureTime, set(templateSet(v), tmpl), set(256, data)))
	}
	f.Fuzz(func(t *testing.T, p []byte) {
		var d Decoder
		r, e := d.Decode("fuzz", fixturePeer, p, fixtureTime, DefaultTTL)
		if e == nil {
			if len(r.Records) > MaxRecords {
				t.Fatal("unbounded records")
			}
			for _, ev := range r.Records {
				_, _ = DecodeEvidence(ev)
			}
		}
	})
}

func TestResourceCapsAndLongVariableFields(t *testing.T) {
	var d Decoder
	// An enterprise variable field exercises the three-octet length form.
	tmpl := append(words(256, 1, 0x8001, 65535), uints(32473)...)
	data := append([]byte{255, 1, 0}, bytes.Repeat([]byte{1}, 256)...)
	r, e := d.Decode("x", fixturePeer, packet(10, 1, 1, fixtureTime, set(2, tmpl), set(256, data)), fixtureTime, DefaultTTL)
	if e != nil || len(r.Records) != 1 {
		t.Fatal(r, e)
	}
	if _, e = DecodeEvidence(r.Records[0]); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < MaxTemplates; i++ {
		tmpl := words(uint16(256+i), 1, 4, 1)
		if _, e = d.Decode("cap", fixturePeer, packet(10, uint32(i), 2, fixtureTime, set(2, tmpl)), fixtureTime, DefaultTTL); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = d.Decode("cap", fixturePeer, packet(10, 100, 2, fixtureTime, set(2, words(400, 1, 4, 1))), fixtureTime, DefaultTTL); !errors.Is(e, ErrLimit) {
		t.Fatal("unbounded templates", e)
	}
	if _, e = d.Decode("records", fixturePeer, packet(10, 1, 3, fixtureTime, set(2, words(256, 1, 4, 1)), set(256, bytes.Repeat([]byte{6}, MaxRecords+1))), fixtureTime, DefaultTTL); !errors.Is(e, ErrLimit) {
		t.Fatal("unbounded record count", e)
	}
	if _, e = d.Decode("fields", fixturePeer, packet(10, 1, 4, fixtureTime, set(2, words(256, MaxFields+1))), fixtureTime, DefaultTTL); !errors.Is(e, ErrLimit) {
		t.Fatal("unbounded fields", e)
	}
}

func TestIndependentInputTTLAndNoTimeGuess(t *testing.T) {
	var d Decoder
	tmpl, data := fixture(10)
	d.Decode("long", fixturePeer, packet(10, 1, 1, fixtureTime, set(2, tmpl)), fixtureTime, time.Hour)
	d.Decode("short", fixturePeer, packet(10, 1, 1, fixtureTime.Add(2*time.Minute), set(2, tmpl)), fixtureTime.Add(2*time.Minute), time.Minute)
	r, e := d.Decode("long", fixturePeer, packet(10, 2, 1, fixtureTime.Add(2*time.Minute), set(256, data)), fixtureTime.Add(2*time.Minute), time.Hour)
	if e != nil || len(r.Records) != 1 {
		t.Fatal("short input expired another input", r, e)
	}
	ev := r.Records[0]
	ev.Template = bytes.Clone(ev.Template[:24])
	binary.BigEndian.PutUint16(ev.Template[2:], 5)
	ev.Record = ev.Record[:13]
	f, e := DecodeEvidence(ev)
	if e != nil || f.Start != nil || f.End != nil || f.TimeBasis != "exporter_export_time" {
		t.Fatal("time invented", f, e)
	}
}
