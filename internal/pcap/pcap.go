// Package pcap reads classic libpcap capture files (the format tcpdump -w
// writes) and decodes just enough of each packet for flow timing analysis:
// timestamps, IP addresses, transport ports and sizes.
//
// Supported link types: Ethernet (with 802.1Q/802.1ad tags), Linux cooked
// capture v1 and v2, raw IP, and BSD loopback. Supported network layers:
// IPv4 and IPv6 (with common extension headers). Supported transports: UDP
// and TCP. Anything else is counted as skipped. pcapng is not supported.
package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"
)

// Link types (LINKTYPE_* values).
const (
	LinkNull     = 0
	LinkEthernet = 1
	LinkRaw      = 101
	LinkSLL      = 113
	LinkSLL2     = 276
)

// MaxPacketBytes bounds a single captured packet. Larger records are
// treated as corruption rather than allocated.
const MaxPacketBytes = 256 * 1024

// Transport protocol names used in Packet.Proto.
const (
	ProtoUDP = "udp"
	ProtoTCP = "tcp"
)

// ErrPcapNG is returned for pcapng files, which this package does not read.
var ErrPcapNG = errors.New("pcap: pcapng format is not supported; convert with: editcap -F pcap in.pcapng out.pcap")

// Packet is a decoded UDP or TCP packet.
type Packet struct {
	TS    time.Time
	Src   netip.AddrPort
	Dst   netip.AddrPort
	Proto string
	// Len is the packet's original length on the wire.
	Len int
}

// Reader reads packets from a capture.
type Reader struct {
	r        io.Reader
	order    binary.ByteOrder
	nanos    bool
	linkType uint32
	hdr      [16]byte
	buf      []byte
	// Skipped counts records that were not decodable UDP/TCP packets.
	Skipped int
}

// NewReader reads the global header and returns a Reader.
func NewReader(r io.Reader) (*Reader, error) {
	var gh [24]byte
	if _, err := io.ReadFull(r, gh[:]); err != nil {
		return nil, fmt.Errorf("pcap: reading global header: %w", err)
	}
	pr := &Reader{r: r, buf: make([]byte, 0, 2048)}
	switch magic := binary.LittleEndian.Uint32(gh[:4]); magic {
	case 0xa1b2c3d4:
		pr.order = binary.LittleEndian
	case 0xa1b23c4d:
		pr.order, pr.nanos = binary.LittleEndian, true
	case 0xd4c3b2a1:
		pr.order = binary.BigEndian
	case 0x4d3cb2a1:
		pr.order, pr.nanos = binary.BigEndian, true
	case 0x0a0d0d0a:
		return nil, ErrPcapNG
	default:
		return nil, fmt.Errorf("pcap: unknown magic number %#08x", magic)
	}
	pr.linkType = pr.order.Uint32(gh[20:24]) & 0x0fffffff // upper bits carry FCS info
	switch pr.linkType {
	case LinkNull, LinkEthernet, LinkRaw, LinkSLL, LinkSLL2:
	default:
		return nil, fmt.Errorf("pcap: unsupported link type %d", pr.linkType)
	}
	return pr, nil
}

// LinkType returns the capture's link type.
func (r *Reader) LinkType() uint32 { return r.linkType }

// Next returns the next UDP or TCP packet, skipping anything else. It
// returns io.EOF at the end of the capture.
func (r *Reader) Next() (Packet, error) {
	for {
		if _, err := io.ReadFull(r.r, r.hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return Packet{}, io.EOF
			}
			return Packet{}, fmt.Errorf("pcap: reading record header: %w", err)
		}
		sec := r.order.Uint32(r.hdr[0:4])
		frac := r.order.Uint32(r.hdr[4:8])
		incl := r.order.Uint32(r.hdr[8:12])
		orig := r.order.Uint32(r.hdr[12:16])
		if incl > MaxPacketBytes {
			return Packet{}, fmt.Errorf("pcap: record of %d bytes exceeds %d", incl, MaxPacketBytes)
		}
		if cap(r.buf) < int(incl) {
			r.buf = make([]byte, incl)
		}
		data := r.buf[:incl]
		if _, err := io.ReadFull(r.r, data); err != nil {
			return Packet{}, fmt.Errorf("pcap: truncated record: %w", err)
		}
		nsec := int64(frac) * 1000
		if r.nanos {
			nsec = int64(frac)
		}
		p, ok := decode(r.linkType, data)
		if !ok {
			r.Skipped++
			continue
		}
		p.TS = time.Unix(int64(sec), nsec).UTC()
		p.Len = int(orig)
		return p, nil
	}
}

// ReadAll reads every UDP and TCP packet in a capture.
func ReadAll(rd io.Reader) ([]Packet, error) {
	r, err := NewReader(rd)
	if err != nil {
		return nil, err
	}
	var out []Packet
	for {
		p, err := r.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
}

// Ethernet types.
const (
	etherIPv4  = 0x0800
	etherIPv6  = 0x86dd
	etherVLAN  = 0x8100
	etherQinQ  = 0x88a8
	ipProtoTCP = 6
	ipProtoUDP = 17
)

func decode(link uint32, b []byte) (Packet, bool) {
	ethType, payload, ok := stripLink(link, b)
	if !ok {
		return Packet{}, false
	}
	switch ethType {
	case etherIPv4:
		return decodeIPv4(payload)
	case etherIPv6:
		return decodeIPv6(payload)
	default:
		return Packet{}, false
	}
}

// stripLink removes the link-layer header and reports the network protocol
// as an EtherType.
func stripLink(link uint32, b []byte) (ethType uint16, payload []byte, ok bool) {
	switch link {
	case LinkEthernet:
		if len(b) < 14 {
			return 0, nil, false
		}
		ethType, b = binary.BigEndian.Uint16(b[12:14]), b[14:]
		for ethType == etherVLAN || ethType == etherQinQ {
			if len(b) < 4 {
				return 0, nil, false
			}
			ethType, b = binary.BigEndian.Uint16(b[2:4]), b[4:]
		}
		return ethType, b, true
	case LinkSLL:
		if len(b) < 16 {
			return 0, nil, false
		}
		return binary.BigEndian.Uint16(b[14:16]), b[16:], true
	case LinkSLL2:
		if len(b) < 20 {
			return 0, nil, false
		}
		return binary.BigEndian.Uint16(b[0:2]), b[20:], true
	case LinkNull:
		if len(b) < 4 {
			return 0, nil, false
		}
		// The address family is in the capturing host's byte order.
		le, be := binary.LittleEndian.Uint32(b[:4]), binary.BigEndian.Uint32(b[:4])
		switch {
		case le == 2 || be == 2: // AF_INET
			return etherIPv4, b[4:], true
		case isAFInet6(le) || isAFInet6(be):
			return etherIPv6, b[4:], true
		}
		return 0, nil, false
	case LinkRaw:
		if len(b) == 0 {
			return 0, nil, false
		}
		switch b[0] >> 4 {
		case 4:
			return etherIPv4, b, true
		case 6:
			return etherIPv6, b, true
		}
	}
	return 0, nil, false
}

func decodeIPv4(b []byte) (Packet, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return Packet{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return Packet{}, false
	}
	if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return Packet{}, false // non-first fragment: no transport header
	}
	src := netip.AddrFrom4([4]byte(b[12:16]))
	dst := netip.AddrFrom4([4]byte(b[16:20]))
	return decodeTransport(b[9], src, dst, b[ihl:])
}

func decodeIPv6(b []byte) (Packet, bool) {
	if len(b) < 40 || b[0]>>4 != 6 {
		return Packet{}, false
	}
	next := b[6]
	src := netip.AddrFrom16([16]byte(b[8:24]))
	dst := netip.AddrFrom16([16]byte(b[24:40]))
	b = b[40:]
	for range 8 { // bounded walk over extension headers
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(b) < 8 {
				return Packet{}, false
			}
			n := (int(b[1]) + 1) * 8
			if len(b) < n {
				return Packet{}, false
			}
			next, b = b[0], b[n:]
		case 44: // fragment
			if len(b) < 8 || binary.BigEndian.Uint16(b[2:4])&0xfff8 != 0 {
				return Packet{}, false
			}
			next, b = b[0], b[8:]
		default:
			return decodeTransport(next, src, dst, b)
		}
	}
	return Packet{}, false
}

func decodeTransport(proto byte, src, dst netip.Addr, b []byte) (Packet, bool) {
	var name string
	switch proto {
	case ipProtoUDP:
		if len(b) < 8 {
			return Packet{}, false
		}
		name = ProtoUDP
	case ipProtoTCP:
		if len(b) < 20 {
			return Packet{}, false
		}
		name = ProtoTCP
	default:
		return Packet{}, false
	}
	return Packet{
		Src:   netip.AddrPortFrom(src.Unmap(), binary.BigEndian.Uint16(b[0:2])),
		Dst:   netip.AddrPortFrom(dst.Unmap(), binary.BigEndian.Uint16(b[2:4])),
		Proto: name,
	}, true
}

// isAFInet6 reports whether v is AF_INET6 on any common OS (BSD 24,
// FreeBSD 28, Darwin 30).
func isAFInet6(v uint32) bool { return v == 24 || v == 28 || v == 30 }
