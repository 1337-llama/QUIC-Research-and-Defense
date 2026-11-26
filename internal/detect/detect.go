// Package detect implements reference QUIC detections over Zeek logs.
//
// These are deliberately simple, explainable detections from the detection
// guide (docs/04-detection-guide.md). They exist to show the techniques
// working end to end and to give the scorer something to measure. They are
// not a substitute for tuned production content.
package detect

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/zeeklog"
)

// Detector names.
const (
	LongConnection        = "long-connection"
	NonStandardPort       = "nonstandard-port"
	MissingSNI            = "missing-sni"
	UnapprovedDestination = "unapproved-destination"
	PeriodicConnections   = "periodic-connections"
)

// Alert is one detection.
type Alert struct {
	Detector string         `json:"detector"`
	TS       time.Time      `json:"ts"`
	UID      string         `json:"uid,omitempty"`
	Orig     netip.AddrPort `json:"orig"`
	Resp     netip.AddrPort `json:"resp"`
	Detail   string         `json:"detail"`
}

// Config enables and tunes the detectors. A zero value for a detector's
// main setting disables it.
type Config struct {
	// LongConnection flags QUIC connections lasting at least this long.
	LongConnection time.Duration
	// StandardPorts are the responder ports QUIC is expected on. Any other
	// port is flagged. Empty disables the detector.
	StandardPorts []uint16
	// ApprovedNets are the destinations QUIC may go to. Anything else is
	// flagged. Empty disables the detector.
	ApprovedNets []netip.Prefix
	// PeriodicMinConns is the fewest connections between one client and
	// one server needed to judge periodicity.
	PeriodicMinConns int
	// PeriodicMaxCV is the largest coefficient of variation (stddev / mean)
	// of the gaps between connection starts that still counts as periodic.
	// Human browsing is close to 1; a jittered beacon is far below.
	PeriodicMaxCV float64
	// MissingSNI flags QUIC handshakes with no server name.
	MissingSNI bool
}

// DefaultConfig returns the settings recommended in the detection guide.
func DefaultConfig() Config {
	return Config{
		LongConnection:   time.Hour,
		StandardPorts:    []uint16{443},
		PeriodicMinConns: 5,
		PeriodicMaxCV:    0.35,
		MissingSNI:       true,
	}
}

// Validate checks the configuration.
func (c Config) Validate() error {
	var errs []error
	if c.LongConnection < 0 {
		errs = append(errs, errors.New("long-connection threshold must not be negative"))
	}
	if c.PeriodicMinConns < 0 || c.PeriodicMinConns == 1 || c.PeriodicMinConns == 2 {
		errs = append(errs, errors.New("periodic minimum must be 0 (disabled) or at least 3 connections"))
	}
	if c.PeriodicMinConns > 0 && (c.PeriodicMaxCV <= 0 || c.PeriodicMaxCV >= 1) {
		errs = append(errs, errors.New("periodic max coefficient of variation must be in (0, 1)"))
	}
	for _, p := range c.ApprovedNets {
		if !p.IsValid() {
			errs = append(errs, fmt.Errorf("invalid approved network %v", p))
		}
	}
	return errors.Join(errs...)
}

// Run applies every enabled detector and returns alerts ordered by time.
func Run(cfg Config, conns []zeeklog.Conn, quics []zeeklog.QUIC) ([]Alert, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	quicUIDs := make(map[string]bool, len(quics))
	for _, q := range quics {
		quicUIDs[q.UID] = true
	}
	var qconns []zeeklog.Conn
	for _, c := range conns {
		if c.HasService("quic") || quicUIDs[c.UID] {
			qconns = append(qconns, c)
		}
	}

	var out []Alert
	alert := func(det string, c zeeklog.Conn, detail string) {
		out = append(out, Alert{Detector: det, TS: c.TS, UID: c.UID, Orig: c.Orig, Resp: c.Resp, Detail: detail})
	}
	for _, c := range qconns {
		if cfg.LongConnection > 0 && c.Duration >= cfg.LongConnection {
			alert(LongConnection, c, fmt.Sprintf("QUIC connection lasted %s (threshold %s)", c.Duration.Round(time.Second), cfg.LongConnection))
		}
		if len(cfg.StandardPorts) > 0 && !slices.Contains(cfg.StandardPorts, c.Resp.Port()) {
			alert(NonStandardPort, c, fmt.Sprintf("QUIC on UDP/%d", c.Resp.Port()))
		}
		if len(cfg.ApprovedNets) > 0 && !inAny(cfg.ApprovedNets, c.Resp.Addr()) {
			alert(UnapprovedDestination, c, fmt.Sprintf("QUIC to %s, outside approved networks", c.Resp.Addr()))
		}
	}
	if cfg.MissingSNI {
		for _, q := range quics {
			if q.ServerName == "" {
				out = append(out, Alert{Detector: MissingSNI, TS: q.TS, UID: q.UID, Orig: q.Orig, Resp: q.Resp, Detail: "QUIC handshake without a server name"})
			}
		}
	}
	if cfg.PeriodicMinConns > 0 {
		out = append(out, periodic(cfg, qconns)...)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].TS.Equal(out[j].TS) {
			return out[i].TS.Before(out[j].TS)
		}
		if out[i].Detector != out[j].Detector {
			return out[i].Detector < out[j].Detector
		}
		return out[i].UID < out[j].UID
	})
	return out, nil
}

func inAny(nets []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

type pairKey struct {
	orig netip.Addr
	resp netip.AddrPort
}

// periodic flags client/server pairs whose connection start times are
// regularly spaced.
func periodic(cfg Config, conns []zeeklog.Conn) []Alert {
	groups := make(map[pairKey][]zeeklog.Conn)
	var keys []pairKey
	for _, c := range conns {
		k := pairKey{c.Orig.Addr(), c.Resp}
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], c)
	}
	var out []Alert
	for _, k := range keys {
		g := groups[k]
		if len(g) < cfg.PeriodicMinConns {
			continue
		}
		sort.SliceStable(g, func(i, j int) bool { return g[i].TS.Before(g[j].TS) })
		mean, cv := gapStats(g)
		if mean <= 0 || cv > cfg.PeriodicMaxCV {
			continue
		}
		detail := fmt.Sprintf("%d connections %s -> %s, mean gap %s, coefficient of variation %.2f",
			len(g), k.orig, k.resp, time.Duration(mean).Round(time.Millisecond), cv)
		for _, c := range g {
			out = append(out, Alert{Detector: PeriodicConnections, TS: c.TS, UID: c.UID, Orig: c.Orig, Resp: c.Resp, Detail: detail})
		}
	}
	return out
}

// gapStats returns the mean gap (in nanoseconds) between successive
// connection starts and the coefficient of variation of those gaps.
func gapStats(g []zeeklog.Conn) (mean, cv float64) {
	n := len(g) - 1
	if n < 1 {
		return 0, 0
	}
	gaps := make([]float64, n)
	for i := range n {
		gaps[i] = float64(g[i+1].TS.Sub(g[i].TS))
		mean += gaps[i]
	}
	mean /= float64(n)
	if mean == 0 {
		return 0, 0
	}
	var ss float64
	for _, x := range gaps {
		ss += (x - mean) * (x - mean)
	}
	return mean, math.Sqrt(ss/float64(n)) / mean
}

// MarshalAlerts encodes alerts as JSON Lines.
func MarshalAlerts(alerts []Alert) ([]byte, error) {
	var out []byte
	for _, a := range alerts {
		b, err := json.Marshal(a)
		if err != nil {
			return nil, err
		}
		out = append(append(out, b...), '\n')
	}
	return out, nil
}

// ReadAlerts parses JSON Lines written by MarshalAlerts.
func ReadAlerts(r io.Reader) ([]Alert, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var out []Alert
	for line := 1; sc.Scan(); line++ {
		text := bytes.TrimSpace(sc.Bytes())
		if len(text) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(text))
		dec.DisallowUnknownFields()
		var a Alert
		if err := dec.Decode(&a); err != nil {
			return nil, fmt.Errorf("alerts line %d: %w", line, err)
		}
		if a.Detector == "" || a.TS.IsZero() || !a.Orig.IsValid() || !a.Resp.IsValid() {
			return nil, fmt.Errorf("alerts line %d: detector, ts, orig and resp are required", line)
		}
		out = append(out, a)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("alerts: %w", err)
	}
	return out, nil
}
