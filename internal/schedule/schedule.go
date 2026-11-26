// Package schedule draws the intervals between simulated requests.
//
// Sampling is deterministic for a given seed, so a lab run can be
// reproduced exactly and tests can assert on concrete values.
package schedule

import (
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/profile"
)

// MaxExponentialFactor caps exponential draws at this multiple of the mean.
// Without a cap, rare draws could stall a short lab run for many minutes.
const MaxExponentialFactor = 10

// MinDelay is the floor applied to every draw.
const MinDelay = time.Millisecond

// Sampler produces successive delays for one schedule. It is not safe for
// concurrent use.
type Sampler struct {
	dist     profile.Distribution
	interval float64
	jitter   float64
	rng      *rand.Rand
}

// New returns a Sampler for s seeded with seed. It returns an error for
// distributions it does not know; callers should validate profiles first.
func New(s profile.Schedule, seed uint64) (*Sampler, error) {
	switch s.Distribution {
	case profile.DistJitter, profile.DistExponential:
	default:
		return nil, fmt.Errorf("schedule: unsupported distribution %q", s.Distribution)
	}
	if s.Interval <= 0 {
		return nil, fmt.Errorf("schedule: interval must be positive, got %s", s.Interval)
	}
	return &Sampler{
		dist:     s.Distribution,
		interval: float64(s.Interval.Std()),
		jitter:   s.Jitter,
		// The second PCG word is derived from the seed so that seed 0 is
		// still a well-mixed stream.
		rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), //nolint:gosec // G404: reproducible simulation, not security
	}, nil
}

// Next returns the next delay.
func (s *Sampler) Next() time.Duration {
	var d float64
	switch s.dist {
	case profile.DistExponential:
		d = s.rng.ExpFloat64() * s.interval
		if lim := s.interval * MaxExponentialFactor; d > lim {
			d = lim
		}
	default: // profile.DistJitter
		d = s.interval * (1 + s.jitter*(2*s.rng.Float64()-1))
	}
	if d < float64(MinDelay) {
		return MinDelay
	}
	return time.Duration(d)
}

// Bounds returns the smallest and largest delay Next can return.
func (s *Sampler) Bounds() (lo, hi time.Duration) {
	switch s.dist {
	case profile.DistExponential:
		return MinDelay, time.Duration(s.interval * MaxExponentialFactor)
	default:
		lo = time.Duration(s.interval * (1 - s.jitter))
		hi = time.Duration(s.interval * (1 + s.jitter))
		if lo < MinDelay {
			lo = MinDelay
		}
		return lo, hi
	}
}
