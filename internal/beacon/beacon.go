// Package beacon runs a traffic profile against a lab server.
//
// The Runner owns timing, connection reuse and ground-truth recording. It
// talks to the network only through the Transport and Session interfaces,
// so the QUIC implementation lives in a separate module and the logic here
// is tested with fakes and a fake clock.
//
// The runner sends benign, self-identifying payloads and checks the
// server's acknowledgement. It has no code path that acts on anything the
// server returns.
package beacon

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"time"

	"github.com/1337-llama/quic_research/internal/groundtruth"
	"github.com/1337-llama/quic_research/internal/payload"
	"github.com/1337-llama/quic_research/internal/profile"
	"github.com/1337-llama/quic_research/internal/schedule"
)

// Request is one HTTP request to send on a session.
type Request struct {
	Method    string
	Path      string
	UserAgent string
	Body      []byte
}

// Response is the server's reply.
type Response struct {
	StatusCode int
	Body       []byte
}

// SessionInfo describes an open connection.
type SessionInfo struct {
	Local  netip.AddrPort
	Remote netip.AddrPort
}

// Session is one open QUIC connection.
type Session interface {
	Do(ctx context.Context, req Request) (Response, error)
	Info() SessionInfo
	Close() error
}

// Transport opens sessions to the lab server.
type Transport interface {
	Open(ctx context.Context) (Session, error)
}

// Clock abstracts time so tests can run instantly.
type Clock interface {
	Now() time.Time
	// Sleep waits for d or until ctx is done, returning ctx.Err() if so.
	Sleep(ctx context.Context, d time.Duration) error
}

// RealClock is the wall clock.
type RealClock struct{}

// Now implements Clock.
func (RealClock) Now() time.Time { return time.Now() }

// Sleep implements Clock.
func (RealClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Defaults for Config fields left at zero.
const (
	DefaultMaxConsecutiveFailures = 10
	DefaultRetryBackoff           = 2 * time.Second
)

// ErrTooManyFailures is returned when consecutive failures reach the limit.
var ErrTooManyFailures = errors.New("beacon: too many consecutive failures")

// ErrPermanent marks failures that retrying cannot fix, such as a target
// the safety policy forbids. The runner stops on the first one.
var ErrPermanent = errors.New("beacon: permanent failure")

// Permanent wraps err so that the runner does not retry it.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrPermanent, err)
}

// ErrRecorder is returned when ground truth cannot be recorded. A run that
// cannot record what it did is useless for scoring, so this is fatal.
var ErrRecorder = errors.New("beacon: recording ground truth failed")

// Config configures a Runner.
type Config struct {
	Profile   profile.Profile
	RunID     string
	Seed      uint64
	Transport Transport
	Recorder  groundtruth.Recorder
	Clock     Clock
	Logger    *slog.Logger

	// MaxBeacons stops the run after this many successful beacons (0 = no limit).
	MaxBeacons uint64
	// Duration stops the run after this much time (0 = no limit).
	Duration time.Duration
	// MaxConsecutiveFailures aborts the run (0 = DefaultMaxConsecutiveFailures).
	MaxConsecutiveFailures int
	// RetryBackoff caps the wait after a failure (0 = DefaultRetryBackoff).
	RetryBackoff time.Duration
}

// Stats summarizes a run.
type Stats struct {
	Sessions uint64
	Beacons  uint64
	Failures uint64
}

// Run executes the profile until a stop condition is reached. Canceling
// ctx is a normal way to stop and is not reported as an error.
func Run(ctx context.Context, cfg Config) (Stats, error) {
	r, err := newRunner(cfg)
	if err != nil {
		return Stats{}, err
	}
	return r.run(ctx)
}

type runner struct {
	cfg     Config
	sampler *schedule.Sampler
	sizeRNG *rand.Rand
	padRNG  io.Reader
	log     *slog.Logger
	stats   Stats

	sess     Session
	sessID   uint64
	sessInfo SessionInfo
	sessAt   time.Time
	sessOK   int
}

func newRunner(cfg Config) (*runner, error) {
	if err := cfg.Profile.Validate(); err != nil {
		return nil, err
	}
	switch {
	case cfg.RunID == "":
		return nil, errors.New("beacon: RunID is required")
	case payload.ValidRunID(cfg.RunID) != nil:
		return nil, fmt.Errorf("beacon: %w", payload.ValidRunID(cfg.RunID))
	case cfg.Transport == nil:
		return nil, errors.New("beacon: Transport is required")
	case cfg.Duration < 0:
		return nil, errors.New("beacon: Duration must not be negative")
	case cfg.MaxConsecutiveFailures < 0:
		return nil, errors.New("beacon: MaxConsecutiveFailures must not be negative")
	case cfg.RetryBackoff < 0:
		return nil, errors.New("beacon: RetryBackoff must not be negative")
	}
	if cfg.Recorder == nil {
		cfg.Recorder = groundtruth.Discard
	}
	if cfg.Clock == nil {
		cfg.Clock = RealClock{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.MaxConsecutiveFailures == 0 {
		cfg.MaxConsecutiveFailures = DefaultMaxConsecutiveFailures
	}
	if cfg.RetryBackoff == 0 {
		cfg.RetryBackoff = DefaultRetryBackoff
	}
	sampler, err := schedule.New(cfg.Profile.Schedule, cfg.Seed)
	if err != nil {
		return nil, err
	}
	var seed [32]byte
	binary.LittleEndian.PutUint64(seed[:8], cfg.Seed)
	return &runner{
		cfg:     cfg,
		sampler: sampler,
		// Deterministic, non-security randomness: runs must be reproducible.
		sizeRNG: rand.New(rand.NewPCG(cfg.Seed, 0x5eed)), //nolint:gosec // G404: reproducible simulation, not security
		padRNG:  rand.NewChaCha8(seed),
		log:     cfg.Logger.With("run_id", cfg.RunID, "profile", cfg.Profile.Name),
	}, nil
}

func (r *runner) run(ctx context.Context) (stats Stats, err error) {
	start := r.cfg.Clock.Now()
	var deadline time.Time
	if r.cfg.Duration > 0 {
		deadline = start.Add(r.cfg.Duration)
	}
	defer func() {
		if cerr := r.closeSession(""); cerr != nil && err == nil {
			err = cerr
		}
		stats = r.stats
	}()

	failures := 0
	for seq := uint64(1); ; {
		if ctx.Err() != nil || (!deadline.IsZero() && !r.cfg.Clock.Now().Before(deadline)) {
			return r.stats, nil
		}

		delay, ferr := r.step(ctx, seq)
		switch {
		case ferr == nil:
			failures = 0
			r.stats.Beacons++
			seq++
			if r.cfg.MaxBeacons > 0 && r.stats.Beacons >= r.cfg.MaxBeacons {
				return r.stats, nil
			}
		case errors.Is(ferr, ErrRecorder), errors.Is(ferr, ErrPermanent):
			r.stats.Failures++
			return r.stats, ferr
		case ctx.Err() != nil:
			return r.stats, nil
		default:
			failures++
			r.stats.Failures++
			r.log.Warn("beacon failed", "seq", seq, "consecutive_failures", failures, "error", ferr)
			if failures >= r.cfg.MaxConsecutiveFailures {
				return r.stats, fmt.Errorf("%w (%d): last error: %w", ErrTooManyFailures, failures, ferr)
			}
			delay = min(delay, r.cfg.RetryBackoff)
		}

		if !deadline.IsZero() {
			delay = min(delay, deadline.Sub(r.cfg.Clock.Now()))
		}
		if delay > 0 {
			if serr := r.cfg.Clock.Sleep(ctx, delay); serr != nil {
				return r.stats, nil
			}
		}
	}
}

// step sends one beacon (opening a session if needed) and returns the delay
// before the next one.
func (r *runner) step(ctx context.Context, seq uint64) (time.Duration, error) {
	delay := r.sampler.Next()
	if r.sess == nil {
		if err := r.openSession(ctx); err != nil {
			return delay, err
		}
	}

	req, beacon, err := r.buildRequest(seq)
	if err != nil {
		return delay, err
	}
	sentAt := r.cfg.Clock.Now()
	resp, err := r.sess.Do(ctx, req)
	if err == nil {
		err = r.checkResponse(resp, beacon)
	}

	rec := r.record(groundtruth.KindBeacon, sentAt)
	rec.Seq, rec.BodyBytes = seq, len(req.Body)
	if err != nil {
		rec.Error = err.Error()
	}
	if rerr := r.cfg.Recorder.Record(rec); rerr != nil {
		return delay, fmt.Errorf("%w: %w", ErrRecorder, rerr)
	}

	if err != nil {
		// A failed request poisons the connection; start fresh next time.
		if cerr := r.closeSession(err.Error()); cerr != nil {
			return delay, cerr
		}
		return delay, err
	}
	r.sessOK++
	r.log.Debug("beacon ok", "seq", seq, "session_id", r.sessID, "body_bytes", len(req.Body))

	switch r.cfg.Profile.Connection.Mode {
	case profile.ModePerBeacon:
		return delay, r.closeSession("")
	case profile.ModeRotate:
		if r.cfg.Clock.Now().Sub(r.sessAt) >= r.cfg.Profile.Connection.RotateAfter.Std() {
			return delay, r.closeSession("")
		}
	case profile.ModePersistent:
	}
	return delay, nil
}

func (r *runner) openSession(ctx context.Context) error {
	s, err := r.cfg.Transport.Open(ctx)
	if err != nil {
		return fmt.Errorf("opening session: %w", err)
	}
	r.sess, r.sessInfo, r.sessAt, r.sessOK = s, s.Info(), r.cfg.Clock.Now(), 0
	r.sessID++
	r.stats.Sessions++
	r.log.Info("session opened", "session_id", r.sessID, "local", r.sessInfo.Local, "remote", r.sessInfo.Remote)
	return nil
}

// closeSession closes the current session, if any, and records it. Errors
// from closing the connection are logged, not returned: the session is over
// either way. Only a failure to record it is returned.
func (r *runner) closeSession(reason string) error {
	if r.sess == nil {
		return nil
	}
	if cerr := r.sess.Close(); cerr != nil {
		r.log.Warn("closing session", "session_id", r.sessID, "error", cerr)
	}
	rec := r.record(groundtruth.KindSession, r.sessAt)
	rec.End, rec.Beacons, rec.Error = r.cfg.Clock.Now(), r.sessOK, reason
	r.sess = nil
	r.log.Info("session closed", "session_id", r.sessID, "beacons", rec.Beacons)
	if err := r.cfg.Recorder.Record(rec); err != nil {
		return fmt.Errorf("%w: %w", ErrRecorder, err)
	}
	return nil
}

func (r *runner) record(kind groundtruth.Kind, start time.Time) groundtruth.Record {
	return groundtruth.Record{
		Kind: kind, RunID: r.cfg.RunID, Profile: r.cfg.Profile.Name, Label: r.cfg.Profile.Label,
		SessionID: r.sessID, Local: r.sessInfo.Local, Remote: r.sessInfo.Remote, Start: start,
	}
}

func (r *runner) buildRequest(seq uint64) (Request, payload.Beacon, error) {
	pr := r.cfg.Profile.Request
	req := Request{Method: pr.Method, Path: pr.Path, UserAgent: pr.UserAgent}
	if pr.Method != http.MethodPost {
		return req, payload.Beacon{}, nil
	}
	size := pr.MinBodyBytes
	if span := pr.MaxBodyBytes - pr.MinBodyBytes; span > 0 {
		size += r.sizeRNG.IntN(span + 1)
	}
	b, body, err := payload.NewBeacon(r.cfg.RunID, seq, r.cfg.Clock.Now(), size, r.padRNG)
	if err != nil {
		return Request{}, payload.Beacon{}, err
	}
	req.Body = body
	return req, b, nil
}

func (r *runner) checkResponse(resp Response, b payload.Beacon) error {
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	if r.cfg.Profile.Request.Method == http.MethodPost {
		if _, err := payload.DecodeAck(resp.Body, b); err != nil {
			return err
		}
	}
	return nil
}
