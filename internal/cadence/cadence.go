// Package cadence detects beaconing inside a single long-lived connection.
//
// Flow logs (conn.log) record one line per connection, so a C2 that keeps
// one QUIC connection open for hours shows no periodicity between
// connections. Inside the connection, though, the client wakes up on a
// schedule: a beacon, a keep-alive, another beacon. This package groups a
// capture's client-to-server packets into bursts and flags connections
// whose bursts start at regular intervals.
package cadence

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/detect"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/pcap"
)

// Detector is the name used in alerts.
const Detector = "intra-connection-cadence"

// Config tunes the detector.
type Config struct {
	// ServerPorts identify the server side of a flow (default 443).
	ServerPorts []uint16
	// Proto restricts flows to "udp" (QUIC), "tcp", or "any".
	Proto string
	// BurstGap is the silence that separates two bursts of client packets.
	BurstGap time.Duration
	// MinBursts is the fewest bursts needed to judge regularity.
	MinBursts int
	// MaxCV is the largest coefficient of variation of the gaps between
	// burst starts that still counts as regular.
	MaxCV float64
	// MinInterval ignores flows whose bursts come faster than this on
	// average (interactive or streaming traffic).
	MinInterval time.Duration
}

// DefaultConfig returns settings tuned for QUIC C2 that checks in every few
// seconds to a few minutes.
func DefaultConfig() Config {
	return Config{
		ServerPorts: []uint16{443},
		Proto:       pcap.ProtoUDP,
		BurstGap:    time.Second,
		MinBursts:   8,
		MaxCV:       0.35,
		MinInterval: 2 * time.Second,
	}
}

// Validate checks the configuration.
func (c Config) Validate() error {
	var errs []error
	if len(c.ServerPorts) == 0 {
		errs = append(errs, errors.New("at least one server port is required"))
	}
	switch c.Proto {
	case pcap.ProtoUDP, pcap.ProtoTCP, "any":
	default:
		errs = append(errs, fmt.Errorf("proto %q must be udp, tcp or any", c.Proto))
	}
	if c.BurstGap <= 0 {
		errs = append(errs, errors.New("burst gap must be positive"))
	}
	if c.MinBursts < 3 {
		errs = append(errs, errors.New("minimum bursts must be at least 3"))
	}
	if c.MaxCV <= 0 || c.MaxCV >= 1 {
		errs = append(errs, errors.New("max coefficient of variation must be in (0, 1)"))
	}
	if c.MinInterval < 0 {
		errs = append(errs, errors.New("minimum interval must not be negative"))
	}
	return errors.Join(errs...)
}

// Flow summarizes one connection's client-to-server activity.
type Flow struct {
	Client, Server netip.AddrPort
	Proto          string
	First, Last    time.Time
	ClientPackets  int
	// BurstStarts are the times client bursts began, in order.
	BurstStarts []time.Time

	lastClient time.Time
}

// Stats returns the mean gap between burst starts and its coefficient of
// variation. Both are zero with fewer than two bursts.
func (f Flow) Stats() (mean time.Duration, cv float64) {
	n := len(f.BurstStarts) - 1
	if n < 1 {
		return 0, 0
	}
	var sum float64
	gaps := make([]float64, n)
	for i := range n {
		gaps[i] = float64(f.BurstStarts[i+1].Sub(f.BurstStarts[i]))
		sum += gaps[i]
	}
	m := sum / float64(n)
	if m == 0 {
		return 0, 0
	}
	var ss float64
	for _, g := range gaps {
		ss += (g - m) * (g - m)
	}
	return time.Duration(m), math.Sqrt(ss/float64(n)) / m
}

type flowKey struct {
	client, server netip.AddrPort
	proto          string
}

// Flows groups packets into flows and computes client bursts. Flows are
// ordered by first packet time.
func Flows(pkts []pcap.Packet, cfg Config) []Flow {
	byKey := make(map[flowKey]*Flow)
	var order []flowKey
	sorted := slices.Clone(pkts)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].TS.Before(sorted[j].TS) })
	for _, p := range sorted {
		if cfg.Proto != "any" && p.Proto != cfg.Proto {
			continue
		}
		var k flowKey
		toServer := false
		switch {
		case slices.Contains(cfg.ServerPorts, p.Dst.Port()):
			k, toServer = flowKey{p.Src, p.Dst, p.Proto}, true
		case slices.Contains(cfg.ServerPorts, p.Src.Port()):
			k = flowKey{p.Dst, p.Src, p.Proto}
		default:
			continue
		}
		f, ok := byKey[k]
		if !ok {
			f = &Flow{Client: k.client, Server: k.server, Proto: k.proto, First: p.TS}
			byKey[k] = f
			order = append(order, k)
		}
		if toServer {
			if f.ClientPackets == 0 || p.TS.Sub(f.lastClient) > cfg.BurstGap {
				f.BurstStarts = append(f.BurstStarts, p.TS)
			}
			f.ClientPackets++
			f.lastClient = p.TS
		}
		f.Last = p.TS
	}
	out := make([]Flow, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out
}

// Detect returns one alert per flow with a regular burst cadence.
func Detect(pkts []pcap.Packet, cfg Config) ([]detect.Alert, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	flows := Flows(pkts, cfg)
	out := make([]detect.Alert, 0, len(flows))
	for _, f := range flows {
		if len(f.BurstStarts) < cfg.MinBursts {
			continue
		}
		mean, cv := f.Stats()
		if mean < cfg.MinInterval || cv > cfg.MaxCV {
			continue
		}
		out = append(out, detect.Alert{
			Detector: Detector,
			TS:       f.First,
			Orig:     f.Client,
			Resp:     f.Server,
			Detail: fmt.Sprintf("%d client bursts over %s, mean interval %s, coefficient of variation %.2f",
				len(f.BurstStarts), f.Last.Sub(f.First).Round(time.Second), mean.Round(time.Millisecond), cv),
		})
	}
	return out, nil
}
