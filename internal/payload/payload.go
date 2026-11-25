// Package payload builds and parses the simulator's request and response
// bodies.
//
// Every beacon identifies itself as simulator traffic (Marker) and carries
// only a run ID, a sequence number, a timestamp and random padding. The
// server's acknowledgement carries the same fields back. There is no field
// for instructions in either direction, by design.
package payload

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Marker identifies simulator traffic to anyone who can see inside it.
const Marker = "quic-research/beaconsim"

// MaxBodyBytes bounds every body this package will build or decode.
const MaxBodyBytes = 2 << 20

// MaxRunIDLen bounds run identifiers.
const MaxRunIDLen = 128

// ValidRunID reports whether id is an acceptable run identifier: 1 to
// MaxRunIDLen characters from [A-Za-z0-9._:-]. Keeping run IDs to a plain
// alphabet means they are safe to log and to use in file names.
func ValidRunID(id string) error {
	if id == "" || len(id) > MaxRunIDLen {
		return fmt.Errorf("run id must be 1-%d characters", MaxRunIDLen)
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == ':', c == '-':
		default:
			return fmt.Errorf("run id %q may only contain letters, digits, '.', '_', ':' and '-'", id)
		}
	}
	return nil
}

// Beacon is the client-to-server request body.
type Beacon struct {
	Sim  string    `json:"sim"`
	Run  string    `json:"run"`
	Seq  uint64    `json:"seq"`
	Sent time.Time `json:"sent"`
	Pad  []byte    `json:"pad,omitempty"`
}

// Ack is the server-to-client response body.
type Ack struct {
	Sim      string    `json:"sim"`
	Run      string    `json:"run"`
	Seq      uint64    `json:"seq"`
	Received time.Time `json:"received"`
}

// NewBeacon builds a beacon whose JSON encoding is as close to targetSize
// bytes as possible without exceeding it. If targetSize is smaller than an
// unpadded beacon, the beacon is sent unpadded. Padding bytes are read from
// rnd, which should be a fast, high-entropy source.
func NewBeacon(run string, seq uint64, sent time.Time, targetSize int, rnd io.Reader) (Beacon, []byte, error) {
	if targetSize < 0 || targetSize > MaxBodyBytes {
		return Beacon{}, nil, fmt.Errorf("target size %d must be between 0 and %d", targetSize, MaxBodyBytes)
	}
	if err := ValidRunID(run); err != nil {
		return Beacon{}, nil, err
	}
	b := Beacon{Sim: Marker, Run: run, Seq: seq, Sent: sent.UTC()}
	base, err := json.Marshal(b)
	if err != nil {
		return Beacon{}, nil, fmt.Errorf("encoding beacon: %w", err)
	}
	// A non-empty pad adds `,"pad":""` (9 bytes) plus base64 text, which is
	// 4 bytes for every 3 bytes of padding.
	const padOverhead = len(`,"pad":""`)
	room := targetSize - len(base) - padOverhead
	if room < 4 {
		return b, base, nil
	}
	// room <= targetSize <= MaxBodyBytes, so this cannot overflow.
	padLen := room / 4 * 3
	b.Pad = make([]byte, padLen)
	if _, err := io.ReadFull(rnd, b.Pad); err != nil {
		return Beacon{}, nil, fmt.Errorf("reading padding: %w", err)
	}
	out, err := json.Marshal(b)
	if err != nil {
		return Beacon{}, nil, fmt.Errorf("encoding beacon: %w", err)
	}
	return b, out, nil
}

// DecodeBeacon parses and validates a beacon body.
func DecodeBeacon(data []byte) (Beacon, error) {
	var b Beacon
	if err := decodeStrict(data, &b); err != nil {
		return Beacon{}, fmt.Errorf("decoding beacon: %w", err)
	}
	if err := checkCommon(b.Sim, b.Run); err != nil {
		return Beacon{}, fmt.Errorf("decoding beacon: %w", err)
	}
	return b, nil
}

// NewAck returns the acknowledgement for b.
func NewAck(b Beacon, received time.Time) Ack {
	return Ack{Sim: Marker, Run: b.Run, Seq: b.Seq, Received: received.UTC()}
}

// DecodeAck parses an acknowledgement and checks that it answers want.
func DecodeAck(data []byte, want Beacon) (Ack, error) {
	var a Ack
	if err := decodeStrict(data, &a); err != nil {
		return Ack{}, fmt.Errorf("decoding ack: %w", err)
	}
	if err := checkCommon(a.Sim, a.Run); err != nil {
		return Ack{}, fmt.Errorf("decoding ack: %w", err)
	}
	if a.Run != want.Run || a.Seq != want.Seq {
		return Ack{}, fmt.Errorf("ack is for run %q seq %d, want run %q seq %d", a.Run, a.Seq, want.Run, want.Seq)
	}
	return a, nil
}

func checkCommon(sim, run string) error {
	if sim != Marker {
		return fmt.Errorf("sim marker %q, want %q", sim, Marker)
	}
	if run == "" {
		return errors.New("missing run id")
	}
	return ValidRunID(run)
}

func decodeStrict(data []byte, v any) error {
	if len(data) > MaxBodyBytes {
		return fmt.Errorf("body is %d bytes, limit is %d", len(data), MaxBodyBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected data after JSON object")
	}
	return nil
}
