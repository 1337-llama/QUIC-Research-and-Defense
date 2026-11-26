// Package labeling creates ground truth from sensor logs for traffic the
// simulator did not generate itself: a real browser used as background
// traffic, or a real C2 framework run on a known lab host.
//
// The rule is simple and must hold for the result to be meaningful: every
// matching connection from the named hosts gets the same label. Run
// labeled hosts on dedicated lab addresses that generate nothing else.
package labeling

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/groundtruth"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/payload"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/profile"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/zeeklog"
)

// Spec describes which connections to label and how.
type Spec struct {
	// Hosts are the originating addresses to label.
	Hosts []netip.Addr
	// Services restricts labeling to connections Zeek identified as one of
	// these services (e.g. "quic", "ssl"). Empty matches any service.
	Services []string
	Label    profile.Label
	Profile  string
	RunID    string
}

// Validate checks the spec.
func (s Spec) Validate() error {
	var errs []error
	if len(s.Hosts) == 0 {
		errs = append(errs, errors.New("at least one host is required"))
	}
	for _, h := range s.Hosts {
		if !h.IsValid() {
			errs = append(errs, fmt.Errorf("invalid host %v", h))
		}
	}
	switch s.Label {
	case profile.LabelBenign, profile.LabelMalicious:
	default:
		errs = append(errs, fmt.Errorf("label %q must be %q or %q", s.Label, profile.LabelBenign, profile.LabelMalicious))
	}
	if s.Profile == "" {
		errs = append(errs, errors.New("profile name is required"))
	}
	if err := payload.ValidRunID(s.RunID); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// FromConns returns one session record per matching conn.log entry, in
// conn.log order, with session IDs starting at 1.
func FromConns(conns []zeeklog.Conn, s Spec) ([]groundtruth.Record, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	out := make([]groundtruth.Record, 0, len(conns))
	var id uint64
	for _, c := range conns {
		if !slices.Contains(s.Hosts, c.Orig.Addr().Unmap()) {
			continue
		}
		if len(s.Services) > 0 && !slices.ContainsFunc(s.Services, c.HasService) {
			continue
		}
		id++
		out = append(out, groundtruth.Record{
			Kind:      groundtruth.KindSession,
			RunID:     s.RunID,
			Profile:   s.Profile,
			Label:     s.Label,
			SessionID: id,
			Local:     c.Orig,
			Remote:    c.Resp,
			Transport: transport(c),
			Start:     c.TS,
			End:       c.TS.Add(c.Duration),
		})
	}
	return out, nil
}

// transport maps Zeek's protocol to the ground-truth transport name.
func transport(c zeeklog.Conn) string {
	if strings.EqualFold(c.Proto, "tcp") {
		return "tcp"
	}
	return "quic"
}
