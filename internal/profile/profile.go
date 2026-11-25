// Package profile defines traffic profiles for the beacon simulator.
//
// A profile describes only observable network behavior: how often the
// simulator connects, how long connections live, what requests look like in
// size and shape, and which QUIC transport settings it advertises. Profiles
// carry no capability: the simulator sends benign, self-identifying
// payloads and the lab server never returns instructions.
package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Label is the ground-truth classification of a profile's traffic.
type Label string

// Ground-truth labels.
const (
	LabelMalicious Label = "malicious"
	LabelBenign    Label = "benign"
)

// Distribution selects how intervals between requests are drawn.
type Distribution string

// Supported interval distributions.
const (
	// DistJitter draws uniformly from Interval*(1±Jitter): a C2-style sleep
	// with jitter.
	DistJitter Distribution = "jitter"
	// DistExponential draws from an exponential distribution with mean
	// Interval: the bursty, memoryless pattern of human browsing.
	DistExponential Distribution = "exponential"
)

// ConnectionMode selects how QUIC connections are reused.
type ConnectionMode string

// Supported connection modes.
const (
	// ModePersistent keeps one connection open for the whole run.
	ModePersistent ConnectionMode = "persistent"
	// ModePerBeacon opens a new connection for every request.
	ModePerBeacon ConnectionMode = "per-beacon"
	// ModeRotate reuses a connection until it is RotateAfter old.
	ModeRotate ConnectionMode = "rotate"
)

// Limits enforced by Validate.
const (
	MinInterval   = 10 * time.Millisecond
	MaxInterval   = 24 * time.Hour
	MaxBodyBytes  = 1 << 20
	MaxFlowWindow = 1 << 30
)

// Profile is a complete traffic profile.
type Profile struct {
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Label       Label      `json:"label"`
	Schedule    Schedule   `json:"schedule"`
	Connection  Connection `json:"connection"`
	Request     Request    `json:"request"`
	QUIC        QUIC       `json:"quic"`
}

// Schedule controls request timing.
type Schedule struct {
	Distribution Distribution `json:"distribution"`
	Interval     Duration     `json:"interval"`
	// Jitter is the fraction (0 <= j < 1) of Interval to vary by. It applies
	// only to DistJitter.
	Jitter float64 `json:"jitter,omitempty"`
}

// Connection controls connection reuse.
type Connection struct {
	Mode        ConnectionMode `json:"mode"`
	RotateAfter Duration       `json:"rotate_after,omitempty"`
}

// Request controls the HTTP/3 requests sent on each beacon.
type Request struct {
	Method       string `json:"method"`
	Path         string `json:"path"`
	MinBodyBytes int    `json:"min_body_bytes,omitempty"`
	MaxBodyBytes int    `json:"max_body_bytes,omitempty"`
	UserAgent    string `json:"user_agent,omitempty"`
}

// QUIC holds transport settings the client advertises. Zero values mean
// "use the QUIC library's default".
type QUIC struct {
	HandshakeIdleTimeout           Duration `json:"handshake_idle_timeout,omitempty"`
	MaxIdleTimeout                 Duration `json:"max_idle_timeout,omitempty"`
	KeepAlivePeriod                Duration `json:"keep_alive_period,omitempty"`
	InitialStreamReceiveWindow     uint64   `json:"initial_stream_receive_window,omitempty"`
	InitialConnectionReceiveWindow uint64   `json:"initial_connection_receive_window,omitempty"`
	EnableDatagrams                bool     `json:"enable_datagrams,omitempty"`
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Validate reports every problem with the profile, joined into one error.
func (p Profile) Validate() error {
	var errs []error
	if !nameRE.MatchString(p.Name) {
		errs = append(errs, fmt.Errorf("name %q must match %s", p.Name, nameRE))
	}
	switch p.Label {
	case LabelMalicious, LabelBenign:
	default:
		errs = append(errs, fmt.Errorf("label %q must be %q or %q", p.Label, LabelMalicious, LabelBenign))
	}
	errs = append(errs, p.Schedule.validate()...)
	errs = append(errs, p.Connection.validate()...)
	errs = append(errs, p.Request.validate()...)
	errs = append(errs, p.QUIC.validate()...)
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("invalid profile %q: %w", p.Name, errors.Join(errs...))
}

func (s Schedule) validate() []error {
	var errs []error
	if iv := s.Interval.Std(); iv < MinInterval || iv > MaxInterval {
		errs = append(errs, fmt.Errorf("schedule.interval %s must be between %s and %s", iv, MinInterval, MaxInterval))
	}
	switch s.Distribution {
	case DistJitter:
		if s.Jitter < 0 || s.Jitter >= 1 {
			errs = append(errs, fmt.Errorf("schedule.jitter %v must be in [0, 1)", s.Jitter))
		}
	case DistExponential:
		if s.Jitter != 0 {
			errs = append(errs, errors.New("schedule.jitter must be 0 for the exponential distribution"))
		}
	default:
		errs = append(errs, fmt.Errorf("schedule.distribution %q must be %q or %q", s.Distribution, DistJitter, DistExponential))
	}
	return errs
}

func (c Connection) validate() []error {
	switch c.Mode {
	case ModeRotate:
		if c.RotateAfter <= 0 {
			return []error{errors.New("connection.rotate_after must be positive in rotate mode")}
		}
	case ModePersistent, ModePerBeacon:
		if c.RotateAfter != 0 {
			return []error{errors.New("connection.rotate_after is only valid in rotate mode")}
		}
	default:
		return []error{fmt.Errorf("connection.mode %q must be %q, %q or %q", c.Mode, ModePersistent, ModePerBeacon, ModeRotate)}
	}
	return nil
}

func (r Request) validate() []error {
	var errs []error
	switch r.Method {
	case http.MethodGet:
		if r.MinBodyBytes != 0 || r.MaxBodyBytes != 0 {
			errs = append(errs, errors.New("request body sizes must be 0 for GET"))
		}
	case http.MethodPost:
	default:
		errs = append(errs, fmt.Errorf("request.method %q must be GET or POST", r.Method))
	}
	if !strings.HasPrefix(r.Path, "/") || strings.ContainsAny(r.Path, " \t\r\n") {
		errs = append(errs, fmt.Errorf("request.path %q must start with / and contain no whitespace", r.Path))
	}
	if r.MinBodyBytes < 0 || r.MaxBodyBytes < r.MinBodyBytes || r.MaxBodyBytes > MaxBodyBytes {
		errs = append(errs, fmt.Errorf("request body sizes must satisfy 0 <= min (%d) <= max (%d) <= %d", r.MinBodyBytes, r.MaxBodyBytes, MaxBodyBytes))
	}
	if strings.ContainsAny(r.UserAgent, "\r\n") {
		errs = append(errs, errors.New("request.user_agent must not contain line breaks"))
	}
	return errs
}

func (q QUIC) validate() []error {
	var errs []error
	for _, d := range []struct {
		name string
		v    Duration
	}{
		{"handshake_idle_timeout", q.HandshakeIdleTimeout},
		{"max_idle_timeout", q.MaxIdleTimeout},
		{"keep_alive_period", q.KeepAlivePeriod},
	} {
		if d.v < 0 {
			errs = append(errs, fmt.Errorf("quic.%s must not be negative", d.name))
		}
	}
	if q.KeepAlivePeriod > 0 && q.MaxIdleTimeout > 0 && q.KeepAlivePeriod >= q.MaxIdleTimeout {
		errs = append(errs, fmt.Errorf("quic.keep_alive_period (%s) must be shorter than quic.max_idle_timeout (%s)", q.KeepAlivePeriod, q.MaxIdleTimeout))
	}
	if q.InitialStreamReceiveWindow > MaxFlowWindow || q.InitialConnectionReceiveWindow > MaxFlowWindow {
		errs = append(errs, fmt.Errorf("quic receive windows must not exceed %d bytes", MaxFlowWindow))
	}
	return errs
}

// Load decodes and validates a profile from JSON. Unknown fields are
// rejected so that typos fail loudly instead of silently using defaults.
func Load(r io.Reader) (Profile, error) {
	data, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return Profile{}, fmt.Errorf("reading profile: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Profile
	if err := dec.Decode(&p); err != nil {
		return Profile{}, fmt.Errorf("decoding profile: %w", err)
	}
	if dec.More() {
		return Profile{}, errors.New("decoding profile: unexpected data after the profile object")
	}
	if err := p.Validate(); err != nil {
		return Profile{}, err
	}
	return p, nil
}
