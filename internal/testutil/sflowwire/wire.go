// SPDX-License-Identifier: Apache-2.0
package sflowwire

import "encoding/binary"

func Words(v ...uint32) []byte {
	p := []byte{}
	for _, n := range v {
		p = binary.BigEndian.AppendUint32(p, n)
	}
	return p
}
func Block(tag uint32, p []byte) []byte {
	v := append(Words(tag, uint32(len(p))), p...)
	for len(v)%4 != 0 {
		v = append(v, 0)
	}
	return v
}
func Packet(expanded bool, kind uint32, record []byte) []byte {
	p := Words(5, 1, 0xc00002fe, 7, 42, 1000, 1)
	s := Words(12, 1, 100, 2000, 3, 1, 2, 1)
	tag := uint32(1)
	if expanded {
		tag = 3
		s = Words(12, 0, 1, 100, 2000, 3, 0, 1, 0, 2, 1)
	}
	s = append(s, Block(kind, record)...)
	return append(p, Block(tag, s)...)
}
func IPv4() []byte { return Words(60, 6, 0xc0000201, 0xc0000202, 12345, 445, 2, 0) }
