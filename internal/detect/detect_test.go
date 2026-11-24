package detect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/1337-llama/quic_research/internal/zeeklog"
)

var t0 = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

type connOpt func(*zeeklog.Conn)

func conn(uid, orig, resp string, at time.Duration, opts ...connOpt) zeeklog.Conn {
	c := zeeklog.Conn{
		UID: uid, TS: t0.Add(at), Proto: "udp", Service: []string{"quic"}, Duration: time.Second,
		Endpoints: zeeklog.Endpoints{Orig: netip.MustParseAddrPort(orig), Resp: netip.MustParseAddrPort(resp)},
	}
	for _, o := range opts {
		o(&c)
	}
	return c
}

func lasting(d time.Duration) connOpt { return func(c *zeeklog.Conn) { c.Duration = d } }
func service(s ...string) connOpt     { return func(c *zeeklog.Conn) { c.Service = s } }

func onlyDetector(alerts []Alert, det string) []Alert {
	var out []Alert
	for _, a := range alerts {
		if a.Detector == det {
			out = append(out, a)
		}
	}
	return out
}

func TestLongConnection(t *testing.T) {
	t.Parallel()
	cfg := Config{LongConnection: time.Hour}
	conns := []zeeklog.Conn{
		conn("long", "10.0.0.2:5000", "10.0.0.1:443", 0, lasting(2*time.Hour)),
		conn("exact", "10.0.0.2:5001", "10.0.0.1:443", 0, lasting(time.Hour)),
		conn("short", "10.0.0.2:5002", "10.0.0.1:443", 0, lasting(59*time.Minute)),
		conn("not-quic", "10.0.0.2:5003", "10.0.0.1:443", 0, lasting(3*time.Hour), service("dns")),
	}
	alerts, err := Run(cfg, conns, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 2 || alerts[0].UID != "exact" || alerts[1].UID != "long" {
		t.Fatalf("alerts = %+v", alerts)
	}
	if !strings.Contains(alerts[1].Detail, "2h0m0s") {
		t.Errorf("detail = %q", alerts[1].Detail)
	}
}

func TestQUICIdentifiedByQUICLogToo(t *testing.T) {
	t.Parallel()
	c := conn("u1", "10.0.0.2:5000", "10.0.0.1:443", 0, lasting(2*time.Hour), service())
	q := zeeklog.QUIC{UID: "u1", TS: t0, ServerName: "x", Endpoints: c.Endpoints}
	alerts, err := Run(Config{LongConnection: time.Hour}, []zeeklog.Conn{c}, []zeeklog.QUIC{q})
	if err != nil || len(alerts) != 1 {
		t.Fatalf("alerts = %+v, err = %v", alerts, err)
	}
}

func TestNonStandardPortAndUnapprovedDestination(t *testing.T) {
	t.Parallel()
	cfg := Config{StandardPorts: []uint16{443}, ApprovedNets: []netip.Prefix{netip.MustParsePrefix("172.28.0.20/32")}}
	conns := []zeeklog.Conn{
		conn("cdn", "172.28.0.40:5000", "172.28.0.20:443", 0),
		conn("c2", "172.28.0.30:5000", "172.28.0.10:443", time.Second),
		conn("odd-port", "172.28.0.30:5001", "172.28.0.20:8443", 2*time.Second),
	}
	alerts, err := Run(cfg, conns, nil)
	if err != nil {
		t.Fatal(err)
	}
	un := onlyDetector(alerts, UnapprovedDestination)
	if len(un) != 1 || un[0].UID != "c2" {
		t.Errorf("unapproved = %+v", un)
	}
	np := onlyDetector(alerts, NonStandardPort)
	if len(np) != 1 || np[0].UID != "odd-port" || !strings.Contains(np[0].Detail, "UDP/8443") {
		t.Errorf("nonstandard = %+v", np)
	}
}

func TestMissingSNI(t *testing.T) {
	t.Parallel()
	ep := zeeklog.Endpoints{Orig: netip.MustParseAddrPort("10.0.0.2:5000"), Resp: netip.MustParseAddrPort("10.0.0.1:443")}
	qs := []zeeklog.QUIC{{UID: "a", TS: t0, Endpoints: ep, ServerName: "c2"}, {UID: "b", TS: t0, Endpoints: ep}}
	alerts, err := Run(Config{MissingSNI: true}, nil, qs)
	if err != nil || len(alerts) != 1 || alerts[0].UID != "b" || alerts[0].Detector != MissingSNI {
		t.Fatalf("alerts = %+v, err = %v", alerts, err)
	}
	if alerts, _ := Run(Config{}, nil, qs); len(alerts) != 0 {
		t.Errorf("disabled detector fired: %+v", alerts)
	}
}

// series builds n connections from one client to one server whose start
// gaps come from gap().
func series(prefix, orig, resp string, n int, gap func() time.Duration) []zeeklog.Conn {
	var out []zeeklog.Conn
	at := time.Duration(0)
	host, _, _ := strings.Cut(orig, ":")
	for i := range n {
		out = append(out, conn(fmt.Sprintf("%s%d", prefix, i), fmt.Sprintf("%s:%d", host, 40000+i), resp, at))
		at += gap()
	}
	return out
}

func TestPeriodicSeparatesBeaconsFromBrowsing(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(1, 2))
	beacon := series("b", "10.0.0.30:0", "10.0.0.10:443", 12, func() time.Duration {
		return time.Duration((1 + 0.2*(2*rng.Float64()-1)) * float64(time.Minute)) // ±20% jitter
	})
	browse := series("h", "10.0.0.40:0", "10.0.0.20:443", 30, func() time.Duration {
		return time.Duration(rng.ExpFloat64() * float64(20*time.Second))
	})
	few := series("f", "10.0.0.50:0", "10.0.0.10:443", 4, func() time.Duration { return time.Minute })
	cfg := Config{PeriodicMinConns: 5, PeriodicMaxCV: 0.35}
	alerts, err := Run(cfg, append(append(beacon, browse...), few...), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != len(beacon) {
		t.Fatalf("got %d alerts, want one per beacon connection (%d): %+v", len(alerts), len(beacon), alerts)
	}
	for _, a := range alerts {
		if !strings.HasPrefix(a.UID, "b") {
			t.Errorf("unexpected periodic alert on %s", a.UID)
		}
		if !strings.Contains(a.Detail, "12 connections") {
			t.Errorf("detail = %q", a.Detail)
		}
	}
}

func TestPeriodicIgnoresSimultaneousConnections(t *testing.T) {
	t.Parallel()
	same := series("s", "10.0.0.30:0", "10.0.0.10:443", 6, func() time.Duration { return 0 })
	alerts, err := Run(Config{PeriodicMinConns: 5, PeriodicMaxCV: 0.35}, same, nil)
	if err != nil || len(alerts) != 0 {
		t.Fatalf("alerts = %+v, err = %v", alerts, err)
	}
}

func TestGapStats(t *testing.T) {
	t.Parallel()
	if m, cv := gapStats(nil); m != 0 || cv != 0 {
		t.Error("empty input")
	}
	g := series("x", "10.0.0.1:0", "10.0.0.2:443", 4, func() time.Duration { return 10 * time.Second })
	m, cv := gapStats(g)
	if time.Duration(m) != 10*time.Second || cv != 0 {
		t.Errorf("gapStats = %v, %v", time.Duration(m), cv)
	}
}

func TestDefaultConfigAndValidate(t *testing.T) {
	t.Parallel()
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	bad := []Config{
		{LongConnection: -1},
		{PeriodicMinConns: 2, PeriodicMaxCV: 0.3},
		{PeriodicMinConns: -1},
		{PeriodicMinConns: 5, PeriodicMaxCV: 0},
		{PeriodicMinConns: 5, PeriodicMaxCV: 1},
		{ApprovedNets: []netip.Prefix{{}}},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("config %d accepted: %+v", i, c)
		}
		if _, err := Run(c, nil, nil); err == nil {
			t.Errorf("Run accepted config %d", i)
		}
	}
}

func TestAlertsAreOrderedAndStable(t *testing.T) {
	t.Parallel()
	conns := []zeeklog.Conn{
		conn("z", "10.0.0.2:1", "8.8.8.8:8443", 2*time.Second, lasting(2*time.Hour)),
		conn("a", "10.0.0.2:2", "8.8.8.8:8443", time.Second),
	}
	cfg := Config{LongConnection: time.Hour, StandardPorts: []uint16{443}, ApprovedNets: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	alerts, err := Run(cfg, conns, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range alerts {
		got = append(got, a.UID+":"+a.Detector)
	}
	want := "a:nonstandard-port a:unapproved-destination z:long-connection z:nonstandard-port z:unapproved-destination"
	if strings.Join(got, " ") != want {
		t.Errorf("order = %v\nwant    %v", got, want)
	}
}

func TestMarshalAlerts(t *testing.T) {
	t.Parallel()
	in := []Alert{{Detector: "d", TS: t0, UID: "u", Orig: netip.MustParseAddrPort("10.0.0.1:1"), Resp: netip.MustParseAddrPort("10.0.0.2:443"), Detail: "x"}}
	b, err := MarshalAlerts(in)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(b, []byte("\n")) != 1 {
		t.Fatalf("output = %q", b)
	}
	var back Alert
	if err := json.Unmarshal(bytes.TrimSpace(b), &back); err != nil || back != in[0] {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
	if b, err := MarshalAlerts(nil); err != nil || len(b) != 0 {
		t.Errorf("empty = %q, %v", b, err)
	}
	read, err := ReadAlerts(bytes.NewReader(append([]byte("\n"), b...)))
	if err != nil || len(read) != 1 || read[0] != in[0] {
		t.Fatalf("ReadAlerts = %+v, %v", read, err)
	}
}

func TestReadAlertsErrors(t *testing.T) {
	t.Parallel()
	for name, in := range map[string]string{
		"bad json":      `{`,
		"unknown field": `{"detector":"d","ts":"2026-11-23T12:00:00Z","orig":"10.0.0.1:1","resp":"10.0.0.2:443","x":1}`,
		"missing ts":    `{"detector":"d","orig":"10.0.0.1:1","resp":"10.0.0.2:443"}`,
		"missing resp":  `{"detector":"d","ts":"2026-11-23T12:00:00Z","orig":"10.0.0.1:1"}`,
		"too long":      strings.Repeat("x", 2<<20),
	} {
		if _, err := ReadAlerts(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
