// SPDX-License-Identifier: Apache-2.0
// Package flowwire supplies protocol fixtures to integration tests only.
package flowwire

import (
	"encoding/binary"
	"time"
)

// Packet exports 192.0.2.1:12345 -> 192.0.2.2:445 TCP in domain 42,
// beginning two seconds and ending one second before export.
func Packet(version uint16, at time.Time, withTemplate bool) []byte {
	words := func(v ...uint16) []byte {
		p := make([]byte, len(v)*2)
		for i, x := range v {
			binary.BigEndian.PutUint16(p[i*2:], x)
		}
		return p
	}
	set := func(id uint16, p []byte) []byte { return append(words(id, uint16(len(p)+4)), p...) }
	tmpl := words(256, 7, 8, 4, 12, 4, 7, 2, 11, 2, 4, 1)
	data := append([]byte{192, 0, 2, 1, 192, 0, 2, 2}, words(12345, 445)...)
	data = append(data, 6)
	var p []byte
	templateSet := uint16(0)
	if version == 9 {
		p = make([]byte, 20)
		binary.BigEndian.PutUint16(p, 9)
		binary.BigEndian.PutUint16(p[2:], 2)
		binary.BigEndian.PutUint32(p[4:], 10000)
		binary.BigEndian.PutUint32(p[8:], uint32(at.Unix()))
		binary.BigEndian.PutUint32(p[12:], 100)
		binary.BigEndian.PutUint32(p[16:], 42)
		tmpl = append(tmpl, words(22, 4, 21, 4)...)
		times := make([]byte, 8)
		binary.BigEndian.PutUint32(times, 8000)
		binary.BigEndian.PutUint32(times[4:], 9000)
		data = append(data, times...)
	} else {
		p = make([]byte, 16)
		binary.BigEndian.PutUint16(p, 10)
		binary.BigEndian.PutUint32(p[4:], uint32(at.Unix()))
		binary.BigEndian.PutUint32(p[8:], 100)
		binary.BigEndian.PutUint32(p[12:], 42)
		templateSet = 2
		tmpl = append(tmpl, words(152, 8, 153, 8)...)
		times := make([]byte, 16)
		binary.BigEndian.PutUint64(times, uint64(at.Add(-2*time.Second).UnixMilli()))
		binary.BigEndian.PutUint64(times[8:], uint64(at.Add(-time.Second).UnixMilli()))
		data = append(data, times...)
	}
	if withTemplate {
		p = append(p, set(templateSet, tmpl)...)
	}
	p = append(p, set(256, data)...)
	if version == 10 {
		binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	}
	return p
}
