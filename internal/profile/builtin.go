package profile

import (
	"fmt"
	"sort"
	"time"
)

// The built-in profiles approximate the *published network behavior* of
// real QUIC C2 families and of ordinary browsing. They are not
// reimplementations of any tool: they only shape timing, connection reuse,
// request sizes and advertised transport settings.
var builtins = []Profile{
	{
		Name: "merlin-like",
		Description: "One long-lived HTTP/3 connection with keep-alives and ~30s jittered POST beacons. " +
			"Modeled on the Merlin behavior described by Active Countermeasures (30s client idle timeout, " +
			"~15s client cadence, near-24h connections).",
		Label:      LabelMalicious,
		Schedule:   Schedule{Distribution: DistJitter, Interval: Duration(30 * time.Second), Jitter: 0.1},
		Connection: Connection{Mode: ModePersistent},
		Request:    Request{Method: "POST", Path: "/", MinBodyBytes: 64, MaxBodyBytes: 4096, UserAgent: "beaconsim/merlin-like"},
		QUIC: QUIC{
			MaxIdleTimeout:  Duration(30 * time.Second),
			KeepAlivePeriod: Duration(15 * time.Second),
		},
	},
	{
		Name: "quicagent-like",
		Description: "A fresh HTTP/3 connection for every ~60s jittered POST beacon carrying an " +
			"encrypted-looking body. Modeled on the QUICAgent behavior reported by Seqrite.",
		Label:      LabelMalicious,
		Schedule:   Schedule{Distribution: DistJitter, Interval: Duration(60 * time.Second), Jitter: 0.2},
		Connection: Connection{Mode: ModePerBeacon},
		Request:    Request{Method: "POST", Path: "/api/v1/update", MinBodyBytes: 128, MaxBodyBytes: 1024, UserAgent: "beaconsim/quicagent-like"},
	},
	{
		Name: "low-and-slow",
		Description: "Infrequent beacons (~15m, 50% jitter) on fresh connections: a hard case for " +
			"periodicity and long-connection detections.",
		Label:      LabelMalicious,
		Schedule:   Schedule{Distribution: DistJitter, Interval: Duration(15 * time.Minute), Jitter: 0.5},
		Connection: Connection{Mode: ModePerBeacon},
		Request:    Request{Method: "POST", Path: "/sync", MinBodyBytes: 32, MaxBodyBytes: 512, UserAgent: "beaconsim/low-and-slow"},
	},
	{
		Name: "rotating-session",
		Description: "Beacons every ~20s on a connection replaced every 10 minutes, to defeat simple " +
			"long-connection thresholds while staying periodic.",
		Label:      LabelMalicious,
		Schedule:   Schedule{Distribution: DistJitter, Interval: Duration(20 * time.Second), Jitter: 0.25},
		Connection: Connection{Mode: ModeRotate, RotateAfter: Duration(10 * time.Minute)},
		Request:    Request{Method: "POST", Path: "/events", MinBodyBytes: 64, MaxBodyBytes: 2048, UserAgent: "beaconsim/rotating-session"},
		QUIC:       QUIC{MaxIdleTimeout: Duration(60 * time.Second), KeepAlivePeriod: Duration(20 * time.Second)},
	},
	{
		Name: "browser-like",
		Description: "Benign background: bursty GET requests (exponential gaps, mean 20s) on short-lived " +
			"connections, like a person browsing a site.",
		Label:      LabelBenign,
		Schedule:   Schedule{Distribution: DistExponential, Interval: Duration(20 * time.Second)},
		Connection: Connection{Mode: ModePerBeacon},
		Request:    Request{Method: "GET", Path: "/", UserAgent: "beaconsim/browser-like"},
		QUIC:       QUIC{MaxIdleTimeout: Duration(30 * time.Second)},
	},
}

// Builtin returns copies of the built-in profiles, sorted by name.
func Builtin() []Profile {
	out := make([]Profile, len(builtins))
	copy(out, builtins)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Lookup returns the built-in profile with the given name.
func Lookup(name string) (Profile, error) {
	for _, p := range builtins {
		if p.Name == name {
			return p, nil
		}
	}
	names := make([]string, 0, len(builtins))
	for _, p := range Builtin() {
		names = append(names, p.Name)
	}
	return Profile{}, fmt.Errorf("unknown profile %q (built-in profiles: %v)", name, names)
}
