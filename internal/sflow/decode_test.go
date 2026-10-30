// SPDX-License-Identifier: Apache-2.0
package sflow

import (
	"encoding/binary"
	"github.com/rkislov/cerber/internal/testutil/sflowwire"
	"testing"
)

func TestSamplesAndMalformedFrames(t *testing.T) {
	for _, expanded := range []bool{false, true} {
		p := sflowwire.Packet(expanded, 3, sflowwire.IPv4())
		v, e := Decode(p)
		if e != nil || len(v) != 1 {
			t.Fatal(v, e)
		}
		s := v[0]
		if s.Source != "192.0.2.1" || s.DestinationPort != 445 || s.Rate != 100 || s.Input != 1 || s.Output != 2 || s.Agent != "192.0.2.254" {
			t.Fatal(s)
		}
		for n := 0; n < len(p); n++ {
			if _, e := Decode(p[:n]); e == nil {
				t.Fatalf("accepted truncated datagram %d", n)
			}
		}
		if _, e := Decode(append(p, 0)); e == nil {
			t.Fatal("trailing bytes")
		}
	}
	p := sflowwire.Packet(false, 9999, []byte{1, 2, 3})
	v, e := Decode(p)
	if e != nil || len(v) != 1 || v[0].Source != "" {
		t.Fatal("invented connection", v, e)
	}
	p = sflowwire.Packet(false, 3, sflowwire.IPv4())
	binary.BigEndian.PutUint32(p[24:28], 0xffffffff)
	if _, e = Decode(p); e == nil {
		t.Fatal("sample count limit")
	}
}
func TestHeaderVLANFragmentsAndIPv6(t *testing.T) {
	ip := make([]byte, 24)
	ip[0] = 0x45
	ip[3] = 24
	ip[9] = 6
	copy(ip[12:], []byte{192, 0, 2, 1, 192, 0, 2, 2, 0x30, 0x39, 1, 0xbd})
	eth := make([]byte, 18)
	eth[12] = 0x81
	eth[16] = 8
	header := append(eth, ip...)
	raw := append(sflowwire.Words(1, 64, 4, uint32(len(header))), header...)
	for len(raw)%4 != 0 {
		raw = append(raw, 0)
	}
	v, e := Decode(sflowwire.Packet(false, 1, raw))
	if e != nil || v[0].SourcePort != 12345 || v[0].DestinationPort != 445 {
		t.Fatal(v, e)
	}
	ip[7] = 1
	s := Sample{}
	if !ipHeader(11, ip, &s) || s.SourcePort != 0 {
		t.Fatal("fragment ports invented", s)
	}
	ipv6 := make([]byte, 52)
	ipv6[0] = 0x60
	ipv6[5] = 12
	ipv6[6] = 44
	ipv6[8] = 0x20
	ipv6[9] = 1
	ipv6[24] = 0x20
	ipv6[25] = 1
	ipv6[40] = 6
	copy(ipv6[48:], []byte{0x30, 0x39, 1, 0xbd})
	s = Sample{}
	if !ipHeader(12, ipv6, &s) || s.DestinationPort != 445 {
		t.Fatal(s)
	}
	ipv6[43] = 8
	s = Sample{}
	if !ipHeader(12, ipv6, &s) || s.DestinationPort != 0 {
		t.Fatal("IPv6 fragment ports", s)
	}
}
func FuzzDecode(f *testing.F) {
	f.Add(sflowwire.Packet(false, 3, sflowwire.IPv4()))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, p []byte) {
		v, e := Decode(p)
		if e == nil && len(v) > 100 {
			t.Fatal("unbounded samples")
		}
	})
}
