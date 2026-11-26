package cadence

import (
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/pcap"
)

var (
	t0     = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	server = netip.MustParseAddrPort("172.28.0.10:443")
)

func client(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("172.28.0.30"), port)
}

// burst emits a short exchange: a few client packets and server replies.
func burst(at time.Time, c netip.AddrPort, proto string) []pcap.Packet {
	return []pcap.Packet{
		{TS: at, Src: c, Dst: server, Proto: proto, Len: 1200},
		{TS: at.Add(2 * time.Millisecond), Src: server, Dst: c, Proto: proto, Len: 1200},
		{TS: at.Add(4 * time.Millisecond), Src: c, Dst: server, Proto: proto, Len: 60},
		{TS: at.Add(30 * time.Millisecond), Src: c, Dst: server, Proto: proto, Len: 60},
	}
}

// series builds n bursts on one flow with gaps from gap().
func series(c netip.AddrPort, n int, proto string, gap func() time.Duration) []pcap.Packet {
	var out []pcap.Packet
	at := t0
	for range n {
		out = append(out, burst(at, c, proto)...)
		at = at.Add(gap())
	}
	return out
}

func TestDetectsRegularBeaconingInOneConnection(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(1, 2))
	// Merlin-like: keep-alive/beacon wakeups every ~15s with small jitter.
	beacon := series(client(40001), 24, pcap.ProtoUDP, func() time.Duration {
		return time.Duration((1 + 0.15*(2*rng.Float64()-1)) * float64(15*time.Second))
	})
	// Browsing-like: irregular activity on one long connection.
	browse := series(client(40002), 24, pcap.ProtoUDP, func() time.Duration {
		return time.Duration(rng.ExpFloat64()*float64(20*time.Second)) + 2*time.Second
	})
	// Too few bursts to judge.
	short := series(client(40003), 5, pcap.ProtoUDP, func() time.Duration { return 15 * time.Second })
	// Streaming: very frequent, regular bursts below MinInterval.
	stream := series(client(40004), 50, pcap.ProtoUDP, func() time.Duration { return 1500 * time.Millisecond })
	// Unrelated traffic on another port, and server-initiated noise.
	other := series(netip.MustParseAddrPort("172.28.0.30:5353"), 30, pcap.ProtoUDP, func() time.Duration { return 15 * time.Second })
	for i := range other {
		other[i].Dst = netip.MustParseAddrPort("172.28.0.2:5353")
	}

	var pkts []pcap.Packet
	for _, s := range [][]pcap.Packet{beacon, browse, short, stream, other} {
		pkts = append(pkts, s...)
	}
	rng.Shuffle(len(pkts), func(i, j int) { pkts[i], pkts[j] = pkts[j], pkts[i] }) // order must not matter

	alerts, err := Detect(pkts, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1 (the beaconing flow): %+v", len(alerts), alerts)
	}
	a := alerts[0]
	if a.Detector != Detector || a.Orig != client(40001) || a.Resp != server || !a.TS.Equal(t0) {
		t.Errorf("alert = %+v", a)
	}
	if !strings.Contains(a.Detail, "24 client bursts") {
		t.Errorf("detail = %q", a.Detail)
	}
}

func TestFlowsBurstsAndDirection(t *testing.T) {
	t.Parallel()
	pkts := series(client(40001), 3, pcap.ProtoUDP, func() time.Duration { return 10 * time.Second })
	// A server-only packet after the last burst extends Last but adds no burst.
	pkts = append(pkts, pcap.Packet{TS: t0.Add(25 * time.Second), Src: server, Dst: client(40001), Proto: pcap.ProtoUDP})
	flows := Flows(pkts, DefaultConfig())
	if len(flows) != 1 {
		t.Fatalf("flows = %+v", flows)
	}
	f := flows[0]
	if f.Client != client(40001) || f.Server != server || f.ClientPackets != 9 || len(f.BurstStarts) != 3 {
		t.Errorf("flow = %+v", f)
	}
	if !f.Last.Equal(t0.Add(25 * time.Second)) {
		t.Errorf("Last = %v", f.Last)
	}
	mean, cv := f.Stats()
	if mean != 10*time.Second || cv != 0 {
		t.Errorf("Stats = %s, %v", mean, cv)
	}
	if m, c := (Flow{}).Stats(); m != 0 || c != 0 {
		t.Error("empty flow stats")
	}
	if m, c := (Flow{BurstStarts: []time.Time{t0, t0}}).Stats(); m != 0 || c != 0 {
		t.Error("zero-gap stats")
	}
}

func TestProtoFilter(t *testing.T) {
	t.Parallel()
	tcp := series(client(40010), 10, pcap.ProtoTCP, func() time.Duration { return 15 * time.Second })
	cfg := DefaultConfig()
	if alerts, _ := Detect(tcp, cfg); len(alerts) != 0 {
		t.Errorf("udp-only config flagged TCP: %+v", alerts)
	}
	cfg.Proto = "any"
	if alerts, _ := Detect(tcp, cfg); len(alerts) != 1 {
		t.Errorf("any-proto config missed TCP beaconing: %+v", alerts)
	}
	cfg.Proto = pcap.ProtoTCP
	if alerts, _ := Detect(tcp, cfg); len(alerts) != 1 {
		t.Errorf("tcp config missed TCP beaconing: %+v", alerts)
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []func(*Config){
		func(c *Config) { c.ServerPorts = nil },
		func(c *Config) { c.Proto = "sctp" },
		func(c *Config) { c.BurstGap = 0 },
		func(c *Config) { c.MinBursts = 2 },
		func(c *Config) { c.MaxCV = 0 },
		func(c *Config) { c.MaxCV = 1 },
		func(c *Config) { c.MinInterval = -1 },
	}
	for i, mut := range bad {
		c := DefaultConfig()
		mut(&c)
		if c.Validate() == nil {
			t.Errorf("config %d accepted", i)
		}
		if _, err := Detect(nil, c); err == nil {
			t.Errorf("Detect accepted config %d", i)
		}
	}
}
