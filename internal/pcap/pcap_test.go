package pcap_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/pcap"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/pcap/pcaptest"
)

var (
	t0     = time.Date(2026, 11, 25, 12, 0, 0, 123456000, time.UTC)
	client = netip.MustParseAddrPort("172.28.0.30:41000")
	server = netip.MustParseAddrPort("172.28.0.10:443")
	c6     = netip.MustParseAddrPort("[fd00::30]:41000")
	s6     = netip.MustParseAddrPort("[fd00::10]:443")
)

func readAll(t *testing.T, b []byte) []pcap.Packet {
	t.Helper()
	ps, err := pcap.ReadAll(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return ps
}

func TestEthernetUDPAndTCP(t *testing.T) {
	t.Parallel()
	w := pcaptest.New(pcaptest.Options{LinkType: pcap.LinkEthernet})
	w.UDP(t0, client, server, 1200)
	w.TCP(t0.Add(time.Second), client, server, 100)
	w.UDP(t0.Add(2*time.Second), c6, s6, 50)
	ps := readAll(t, w.Bytes())
	if len(ps) != 3 {
		t.Fatalf("got %d packets", len(ps))
	}
	want := pcap.Packet{TS: t0, Src: client, Dst: server, Proto: pcap.ProtoUDP, Len: 14 + 20 + 8 + 1200}
	if ps[0] != want {
		t.Errorf("packet 0:\n got %+v\nwant %+v", ps[0], want)
	}
	if ps[1].Proto != pcap.ProtoTCP || ps[1].Dst != server {
		t.Errorf("packet 1 = %+v", ps[1])
	}
	if ps[2].Src != c6 || ps[2].Dst != s6 {
		t.Errorf("IPv6 packet = %+v", ps[2])
	}
}

func TestFormatsAndLinkTypes(t *testing.T) {
	t.Parallel()
	ip4 := pcaptest.IP(17, client, server, 10)
	ip6 := pcaptest.IP(17, c6, s6, 10)
	vlan := append(append([]byte{}, pcaptest.Ethernet(ip4)[:12]...), 0x81, 0x00, 0x00, 0x05, 0x08, 0x00)
	vlan = append(vlan, ip4...)
	sll := append(make([]byte, 16), ip4...)
	binary.BigEndian.PutUint16(sll[14:16], 0x0800)
	sll2 := append(make([]byte, 20), ip6...)
	binary.BigEndian.PutUint16(sll2[0:2], 0x86dd)
	null4 := append([]byte{2, 0, 0, 0}, ip4...)
	null6 := append([]byte{0, 0, 0, 30}, ip6...)

	tests := []struct {
		name  string
		opts  pcaptest.Options
		frame []byte
		src   netip.AddrPort
	}{
		{"big endian nanos", pcaptest.Options{LinkType: pcap.LinkEthernet, BigEndian: true, Nanos: true}, pcaptest.Ethernet(ip4), client},
		{"little endian nanos", pcaptest.Options{LinkType: pcap.LinkEthernet, Nanos: true}, pcaptest.Ethernet(ip4), client},
		{"big endian micros", pcaptest.Options{LinkType: pcap.LinkEthernet, BigEndian: true}, pcaptest.Ethernet(ip4), client},
		{"vlan", pcaptest.Options{LinkType: pcap.LinkEthernet}, vlan, client},
		{"linux sll", pcaptest.Options{LinkType: pcap.LinkSLL}, sll, client},
		{"linux sll2 ipv6", pcaptest.Options{LinkType: pcap.LinkSLL2}, sll2, c6},
		{"raw ipv4", pcaptest.Options{LinkType: pcap.LinkRaw}, ip4, client},
		{"raw ipv6", pcaptest.Options{LinkType: pcap.LinkRaw}, ip6, c6},
		{"null ipv4", pcaptest.Options{LinkType: pcap.LinkNull}, null4, client},
		{"null ipv6 big endian family", pcaptest.Options{LinkType: pcap.LinkNull}, null6, c6},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := pcaptest.New(tc.opts)
			w.Record(t0, tc.frame)
			ps := readAll(t, w.Bytes())
			if len(ps) != 1 || ps[0].Src != tc.src || !ps[0].TS.Equal(t0) {
				t.Fatalf("packets = %+v", ps)
			}
		})
	}
}

func TestSkipsUndecodablePackets(t *testing.T) {
	t.Parallel()
	ip4 := pcaptest.IP(17, client, server, 10)
	frag := append([]byte{}, ip4...)
	binary.BigEndian.PutUint16(frag[6:8], 0x0010) // fragment offset != 0
	icmp := append([]byte{}, ip4...)
	icmp[9] = 1
	ip6frag := pcaptest.IP(17, c6, s6, 10)
	ip6frag[6] = 44
	ip6frag = append(ip6frag[:40], append([]byte{17, 0, 0, 0x08, 0, 0, 0, 0}, ip6frag[40:]...)...)
	ip6hop := pcaptest.IP(17, c6, s6, 10)
	ip6hop[6] = 0
	ip6hop = append(ip6hop[:40], append([]byte{17, 0, 0, 0, 0, 0, 0, 0}, ip6hop[40:]...)...)
	arp := pcaptest.Ethernet(ip4)
	binary.BigEndian.PutUint16(arp[12:14], 0x0806)

	w := pcaptest.New(pcaptest.Options{LinkType: pcap.LinkEthernet})
	for _, f := range [][]byte{
		pcaptest.Ethernet(frag), pcaptest.Ethernet(icmp), arp, {1, 2, 3},
		pcaptest.Ethernet(ip4[:15]), pcaptest.Ethernet(ip6frag), pcaptest.Ethernet(pcaptest.IP(6, client, server, 0)[:30]),
	} {
		w.Record(t0, f)
	}
	w.Record(t0, pcaptest.Ethernet(ip6hop)) // extension header walked: decodable
	r, err := pcap.NewReader(bytes.NewReader(w.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.Next()
	if err != nil || p.Src != c6 {
		t.Fatalf("Next = %+v, %v", p, err)
	}
	if r.Skipped != 7 {
		t.Errorf("Skipped = %d, want 7", r.Skipped)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Errorf("want EOF, got %v", err)
	}
	if r.LinkType() != pcap.LinkEthernet {
		t.Errorf("LinkType = %d", r.LinkType())
	}
}

func TestReaderErrors(t *testing.T) {
	t.Parallel()
	good := pcaptest.New(pcaptest.Options{LinkType: pcap.LinkEthernet})
	good.UDP(t0, client, server, 10)
	gb := good.Bytes()

	oversize := append([]byte{}, gb[:24]...)
	oversize = append(oversize, make([]byte, 16)...)
	binary.LittleEndian.PutUint32(oversize[24+8:], pcap.MaxPacketBytes+1)

	badLink := append([]byte{}, gb[:24]...)
	binary.LittleEndian.PutUint32(badLink[20:24], 105)

	ng := []byte{0x0a, 0x0d, 0x0d, 0x0a}
	ng = append(ng, make([]byte, 20)...)

	tests := map[string]struct {
		in   []byte
		want string
	}{
		"empty":        {nil, "global header"},
		"bad magic":    {make([]byte, 24), "unknown magic"},
		"pcapng":       {ng, "pcapng"},
		"bad link":     {badLink, "unsupported link type"},
		"short record": {gb[:24+10], "record header"},
		"truncated":    {gb[:len(gb)-5], "truncated record"},
		"oversize":     {oversize, "exceeds"},
	}
	for name, tc := range tests {
		_, err := pcap.ReadAll(bytes.NewReader(tc.in))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
	if _, err := pcap.ReadAll(bytes.NewReader(ng)); !errors.Is(err, pcap.ErrPcapNG) {
		t.Errorf("pcapng error should wrap ErrPcapNG: %v", err)
	}
}

func FuzzReader(f *testing.F) {
	w := pcaptest.New(pcaptest.Options{LinkType: pcap.LinkEthernet})
	w.UDP(t0, client, server, 20)
	w.TCP(t0, c6, s6, 20)
	f.Add(w.Bytes())
	f.Fuzz(func(t *testing.T, data []byte) {
		ps, err := pcap.ReadAll(bytes.NewReader(data))
		if err != nil {
			return
		}
		for _, p := range ps {
			if !p.Src.IsValid() || !p.Dst.IsValid() || (p.Proto != pcap.ProtoUDP && p.Proto != pcap.ProtoTCP) {
				t.Fatalf("invalid packet %+v", p)
			}
		}
	})
}
