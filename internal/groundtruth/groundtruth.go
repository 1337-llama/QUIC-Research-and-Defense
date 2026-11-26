// Package groundtruth records what the simulator actually did, so that
// detections can be scored against known answers.
//
// Records are JSON Lines. The simulator writes one "beacon" record per
// request and one "session" record when each QUIC connection closes. The
// scorer works from session records, because network sensors log
// connections.
package groundtruth

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/profile"
)

// Kind is the type of a record.
type Kind string

// Record kinds.
const (
	KindSession Kind = "session"
	KindBeacon  Kind = "beacon"
)

// Record is one line of ground truth.
type Record struct {
	Kind      Kind           `json:"kind"`
	RunID     string         `json:"run_id"`
	Profile   string         `json:"profile"`
	Label     profile.Label  `json:"label"`
	SessionID uint64         `json:"session_id"`
	Local     netip.AddrPort `json:"local"`
	Remote    netip.AddrPort `json:"remote"`
	// Transport is the protocol that carried the session ("quic" or "tcp").
	Transport string    `json:"transport,omitempty"`
	Start     time.Time `json:"start"`
	// End is set on session records only.
	End time.Time `json:"end,omitzero"`
	// Seq and BodyBytes are set on beacon records only.
	Seq       uint64 `json:"seq,omitempty"`
	BodyBytes int    `json:"body_bytes,omitempty"`
	// Beacons is the number of successful beacons, on session records only.
	Beacons int `json:"beacons,omitempty"`
	// Error describes a failed beacon or a session that ended in error.
	Error string `json:"error,omitempty"`
}

// Validate checks that a record is internally consistent.
func (r Record) Validate() error {
	var errs []error
	switch r.Kind {
	case KindSession:
		if r.End.IsZero() || r.End.Before(r.Start) {
			errs = append(errs, errors.New("session end must be set and not before start"))
		}
	case KindBeacon:
	default:
		errs = append(errs, fmt.Errorf("unknown kind %q", r.Kind))
	}
	if r.RunID == "" {
		errs = append(errs, errors.New("missing run_id"))
	}
	switch r.Label {
	case profile.LabelBenign, profile.LabelMalicious:
	default:
		errs = append(errs, fmt.Errorf("unknown label %q", r.Label))
	}
	if r.Start.IsZero() {
		errs = append(errs, errors.New("missing start"))
	}
	if !r.Remote.IsValid() {
		errs = append(errs, errors.New("missing remote address"))
	}
	return errors.Join(errs...)
}

// Recorder receives records. Implementations must be safe for concurrent use.
type Recorder interface {
	Record(Record) error
}

// Writer is a Recorder that writes JSON Lines to an io.Writer.
type Writer struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewWriter returns a Writer that writes to w.
func NewWriter(w io.Writer) *Writer { return &Writer{enc: json.NewEncoder(w)} }

// Record validates r and writes it as one line.
func (w *Writer) Record(r Record) error {
	if err := r.Validate(); err != nil {
		return fmt.Errorf("groundtruth: invalid record: %w", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.enc.Encode(r); err != nil {
		return fmt.Errorf("groundtruth: writing record: %w", err)
	}
	return nil
}

// Discard is a Recorder that drops every record.
var Discard Recorder = discard{}

type discard struct{}

func (discard) Record(Record) error { return nil }

// MaxLineBytes bounds a single ground-truth line.
const MaxLineBytes = 1 << 20

// Read parses JSON Lines ground truth. Blank lines are ignored. Errors name
// the offending line.
func Read(r io.Reader) ([]Record, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), MaxLineBytes)
	var out []Record
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(text), &rec); err != nil {
			return nil, fmt.Errorf("groundtruth line %d: %w", line, err)
		}
		if err := rec.Validate(); err != nil {
			return nil, fmt.Errorf("groundtruth line %d: %w", line, err)
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("groundtruth: %w", err)
	}
	return out, nil
}

// Sessions returns the session records in recs, ordered by start time, with
// duplicate (run, session) pairs rejected.
func Sessions(recs []Record) ([]Record, error) {
	type key struct {
		run string
		id  uint64
	}
	seen := make(map[key]bool)
	out := make([]Record, 0, len(recs))
	for _, r := range recs {
		if r.Kind != KindSession {
			continue
		}
		k := key{r.RunID, r.SessionID}
		if seen[k] {
			return nil, fmt.Errorf("groundtruth: duplicate session %d in run %q", r.SessionID, r.RunID)
		}
		seen[k] = true
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out, nil
}
