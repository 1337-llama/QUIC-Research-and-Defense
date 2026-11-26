// Package pcaptest builds synthetic pcap captures for tests.
package pcaptest

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"time"
)

// Writer builds a classic little-endian, microsecond pcap in memory.
type Writer struct {
	buf      bytes.Buffer
	order    binary.ByteOrder
	nanos    bool
	linkType uint32
}

// Options controls the capture format.
type Options struct {
	LinkType  uint32
	BigEndian bool
	Nanos     bool
}

// New returns a Writer with the global header already written.
func New(o Options) *Writer {
	w := &Writer{order: binary.LittleEndian, nanos: o.Nanos, linkType: o.LinkType}
	if o.BigEndian {
		w.order = binary.BigEndian
	}
	magic := uint32(0xa1b2c3d4)
	if o.Nanos {
		magic = 0xa1b23c4d
	}
	var gh [24]byte
	w.order.PutUint32(gh[0:4], magic)
	w.order.PutUint16(gh[4:6], 2)
	w.order.PutUint16(gh[6:8], 4)
	w.order.PutUint32(gh[16:20], 262144)
	w.order.PutUint32(gh[20:24], o.LinkType)
	w.buf.Write(gh[:])
	return w
}

// Record appends a raw frame captured at ts.
func (w *Writer) Record(ts time.Time, frame []byte) {
	var h [16]byte
	frac := uint32(ts.Nanosecond() / 1000)
	if w.nanos {
		frac = uint32(ts.Nanosecond())
	}
	w.order.PutUint32(h[0:4], uint32(ts.Unix()))
	w.order.PutUint32(h[4:8], frac)
	w.order.PutUint32(h[8:12], uint32(len(frame)))
	w.order.PutUint32(h[12:16], uint32(len(frame)))
	w.buf.Write(h[:])
	w.buf.Write(frame)
}

// UDP appends an Ethernet/IP/UDP frame (the Writer must use LinkEthernet).
func (w *Writer) UDP(ts time.Time, src, dst netip.AddrPort, payload int) {
	w.Record(ts, Ethernet(IP(17, src, dst, payload)))
}

// TCP appends an Ethernet/IP/TCP frame.
func (w *Writer) TCP(ts time.Time, src, dst netip.AddrPort, payload int) {
	w.Record(ts, Ethernet(IP(6, src, dst, payload)))
}

// Bytes returns the capture.
func (w *Writer) Bytes() []byte { return w.buf.Bytes() }

// Ethernet wraps an IP packet in an Ethernet header with the right type.
func Ethernet(ip []byte) []byte {
	h := make([]byte, 14, 14+len(ip))
	typ := uint16(0x0800)
	if len(ip) > 0 && ip[0]>>4 == 6 {
		typ = 0x86dd
	}
	binary.BigEndian.PutUint16(h[12:14], typ)
	return append(h, ip...)
}

// IP builds an IPv4 or IPv6 packet (by address family) carrying a UDP (17)
// or TCP (6) header and payload bytes of zeros.
func IP(proto byte, src, dst netip.AddrPort, payload int) []byte {
	var l4 []byte
	if proto == 6 {
		l4 = make([]byte, 20+payload)
		l4[12] = 5 << 4
	} else {
		l4 = make([]byte, 8+payload)
		binary.BigEndian.PutUint16(l4[4:6], uint16(len(l4)))
	}
	binary.BigEndian.PutUint16(l4[0:2], src.Port())
	binary.BigEndian.PutUint16(l4[2:4], dst.Port())

	if src.Addr().Is4() {
		h := make([]byte, 20, 20+len(l4))
		h[0] = 0x45
		binary.BigEndian.PutUint16(h[2:4], uint16(20+len(l4)))
		h[8], h[9] = 64, proto
		s, d := src.Addr().As4(), dst.Addr().As4()
		copy(h[12:16], s[:])
		copy(h[16:20], d[:])
		return append(h, l4...)
	}
	h := make([]byte, 40, 40+len(l4))
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:6], uint16(len(l4)))
	h[6], h[7] = proto, 64
	s, d := src.Addr().As16(), dst.Addr().As16()
	copy(h[8:24], s[:])
	copy(h[24:40], d[:])
	return append(h, l4...)
}
