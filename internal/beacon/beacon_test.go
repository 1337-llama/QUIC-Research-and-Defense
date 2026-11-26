package beacon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/groundtruth"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/labserver"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/profile"
)

var t0 = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

// fakeClock advances only when the runner sleeps.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
	// onSleep, if set, runs before each sleep (e.g. to cancel a context).
	onSleep func(n int)
}

func newClock() *fakeClock { return &fakeClock{now: t0} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	c.sleeps = append(c.sleeps, d)
	n, hook := len(c.sleeps), c.onSleep
	c.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
	return nil
}

// labTransport serves sessions from an in-memory labserver.Handler.
type labTransport struct {
	h        http.Handler
	mu       sync.Mutex
	opens    int
	closes   int
	openErr  func(n int) error
	doErr    func(n int) error
	closeErr error
	dos      int
	reqs     []Request
}

type labSession struct {
	t    *labTransport
	info SessionInfo
}

func (t *labTransport) Open(context.Context) (Session, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.opens++
	if t.openErr != nil {
		if err := t.openErr(t.opens); err != nil {
			return nil, err
		}
	}
	return &labSession{t: t, info: SessionInfo{
		Local:  netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), uint16(40000+t.opens)),
		Remote: netip.MustParseAddrPort("10.0.0.1:443"),
	}}, nil
}

func (s *labSession) Info() SessionInfo { return s.info }

func (s *labSession) Close() error {
	s.t.mu.Lock()
	defer s.t.mu.Unlock()
	s.t.closes++
	return s.t.closeErr
}

func (s *labSession) Do(_ context.Context, req Request) (Response, error) {
	s.t.mu.Lock()
	s.t.dos++
	n := s.t.dos
	s.t.reqs = append(s.t.reqs, req)
	doErr := s.t.doErr
	s.t.mu.Unlock()
	if doErr != nil {
		if err := doErr(n); err != nil {
			return Response{}, err
		}
	}
	hreq := httptest.NewRequest(req.Method, req.Path, bytes.NewReader(req.Body))
	hreq.Header.Set("User-Agent", req.UserAgent)
	rec := httptest.NewRecorder()
	s.t.h.ServeHTTP(rec, hreq)
	return Response{StatusCode: rec.Code, Body: rec.Body.Bytes()}, nil
}

// memRecorder keeps records in memory.
type memRecorder struct {
	mu   sync.Mutex
	recs []groundtruth.Record
	err  func(groundtruth.Record) error
}

func (m *memRecorder) Record(r groundtruth.Record) error {
	if err := r.Validate(); err != nil {
		return fmt.Errorf("runner produced an invalid record: %w", err)
	}
	if m.err != nil {
		if err := m.err(r); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs = append(m.recs, r)
	return nil
}

func (m *memRecorder) kind(k groundtruth.Kind) []groundtruth.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []groundtruth.Record
	for _, r := range m.recs {
		if r.Kind == k {
			out = append(out, r)
		}
	}
	return out
}

func testProfile(mode profile.ConnectionMode) profile.Profile {
	p := profile.Profile{
		Name:       "test",
		Label:      profile.LabelMalicious,
		Schedule:   profile.Schedule{Distribution: profile.DistJitter, Interval: profile.Duration(time.Second)},
		Connection: profile.Connection{Mode: mode},
		Request:    profile.Request{Method: "POST", Path: "/b", MinBodyBytes: 200, MaxBodyBytes: 600, UserAgent: "test-ua"},
	}
	if mode == profile.ModeRotate {
		p.Connection.RotateAfter = profile.Duration(3 * time.Second)
	}
	return p
}

type harness struct {
	clock *fakeClock
	tr    *labTransport
	rec   *memRecorder
	srv   *labserver.Handler
	cfg   Config
}

func newHarness(p profile.Profile) *harness {
	h := &harness{clock: newClock(), rec: &memRecorder{}, srv: labserver.New(nil, nil)}
	h.tr = &labTransport{h: h.srv}
	h.cfg = Config{Profile: p, RunID: "run-test", Seed: 1, Transport: h.tr, Recorder: h.rec, Clock: h.clock}
	return h
}

func (h *harness) run(t *testing.T) Stats {
	t.Helper()
	st, err := Run(context.Background(), h.cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return st
}

func TestPersistentModeUsesOneSession(t *testing.T) {
	t.Parallel()
	h := newHarness(testProfile(profile.ModePersistent))
	h.cfg.MaxBeacons = 5
	st := h.run(t)

	if st != (Stats{Sessions: 1, Beacons: 5}) {
		t.Fatalf("Stats = %+v", st)
	}
	if h.tr.opens != 1 || h.tr.closes != 1 {
		t.Errorf("opens=%d closes=%d", h.tr.opens, h.tr.closes)
	}
	if got := h.srv.Stats().Beacons; got != 5 {
		t.Errorf("server saw %d beacons", got)
	}
	sessions := h.rec.kind(groundtruth.KindSession)
	if len(sessions) != 1 || sessions[0].Beacons != 5 || sessions[0].Error != "" {
		t.Fatalf("sessions = %+v", sessions)
	}
	s := sessions[0]
	if !s.Start.Equal(t0) || !s.End.Equal(t0.Add(4*time.Second)) {
		t.Errorf("session window = %v..%v", s.Start, s.End)
	}
	if s.Local.Port() != 40001 || s.Label != profile.LabelMalicious || s.Profile != "test" {
		t.Errorf("session = %+v", s)
	}
	beacons := h.rec.kind(groundtruth.KindBeacon)
	for i, b := range beacons {
		if b.Seq != uint64(i+1) || b.SessionID != 1 || b.Error != "" || b.BodyBytes == 0 || b.BodyBytes > 600 {
			t.Errorf("beacon %d = %+v", i, b)
		}
	}
	if len(h.clock.sleeps) != 4 {
		t.Errorf("sleeps = %v; the run should stop right after the last beacon", h.clock.sleeps)
	}
}

func TestPerBeaconModeOpensFreshSessions(t *testing.T) {
	t.Parallel()
	h := newHarness(testProfile(profile.ModePerBeacon))
	h.cfg.MaxBeacons = 4
	st := h.run(t)
	if st.Sessions != 4 || st.Beacons != 4 {
		t.Fatalf("Stats = %+v", st)
	}
	ports := map[uint16]bool{}
	for _, s := range h.rec.kind(groundtruth.KindSession) {
		if s.Beacons != 1 {
			t.Errorf("session %d has %d beacons", s.SessionID, s.Beacons)
		}
		ports[s.Local.Port()] = true
	}
	if len(ports) != 4 {
		t.Errorf("expected 4 distinct source ports, got %v", ports)
	}
}

func TestRotateModeReplacesAgedSessions(t *testing.T) {
	t.Parallel()
	h := newHarness(testProfile(profile.ModeRotate))
	h.cfg.MaxBeacons = 8
	h.run(t)
	sessions := h.rec.kind(groundtruth.KindSession)
	if len(sessions) != 2 {
		t.Fatalf("want 2 sessions, got %+v", sessions)
	}
	for _, s := range sessions {
		if s.Beacons != 4 {
			t.Errorf("session %d: %d beacons, want 4", s.SessionID, s.Beacons)
		}
	}
}

func TestDurationStopsWithoutOversleeping(t *testing.T) {
	t.Parallel()
	p := testProfile(profile.ModePersistent)
	p.Schedule.Interval = profile.Duration(10 * time.Second)
	h := newHarness(p)
	h.cfg.Duration = 35 * time.Second
	st := h.run(t)
	if st.Beacons != 4 {
		t.Fatalf("Beacons = %d, want 4 (at 0s, 10s, 20s, 30s)", st.Beacons)
	}
	if end := h.clock.Now(); !end.Equal(t0.Add(35 * time.Second)) {
		t.Errorf("clock ended at +%s, want +35s", end.Sub(t0))
	}
	if last := h.clock.sleeps[len(h.clock.sleeps)-1]; last != 5*time.Second {
		t.Errorf("final sleep = %s, want it trimmed to the deadline", last)
	}
}

func TestGetProfileAgainstLabServer(t *testing.T) {
	t.Parallel()
	p := testProfile(profile.ModePerBeacon)
	p.Label = profile.LabelBenign
	p.Request = profile.Request{Method: "GET", Path: "/", UserAgent: "ua"}
	p.Schedule = profile.Schedule{Distribution: profile.DistExponential, Interval: profile.Duration(time.Second)}
	h := newHarness(p)
	h.cfg.MaxBeacons = 3
	if st := h.run(t); st.Beacons != 3 {
		t.Fatalf("Stats = %+v", st)
	}
	if got := h.srv.Stats(); got.Pages != 3 || got.Beacons != 0 {
		t.Errorf("server stats = %+v", got)
	}
	for _, r := range h.tr.reqs {
		if r.Method != http.MethodGet || len(r.Body) != 0 || r.UserAgent != "ua" {
			t.Errorf("request = %+v", r)
		}
	}
	for _, s := range h.rec.kind(groundtruth.KindSession) {
		if s.Label != profile.LabelBenign {
			t.Errorf("label = %s", s.Label)
		}
	}
}

func TestOpenFailuresAreRetriedWithBackoff(t *testing.T) {
	t.Parallel()
	p := testProfile(profile.ModePersistent)
	p.Schedule.Interval = profile.Duration(time.Minute)
	h := newHarness(p)
	h.cfg.MaxBeacons = 1
	h.cfg.RetryBackoff = 500 * time.Millisecond
	h.tr.openErr = func(n int) error {
		if n <= 2 {
			return errors.New("connection refused")
		}
		return nil
	}
	st := h.run(t)
	if st != (Stats{Sessions: 1, Beacons: 1, Failures: 2}) {
		t.Fatalf("Stats = %+v", st)
	}
	if len(h.clock.sleeps) != 2 || h.clock.sleeps[0] != 500*time.Millisecond || h.clock.sleeps[1] != 500*time.Millisecond {
		t.Errorf("sleeps = %v, want two 500ms backoffs", h.clock.sleeps)
	}
}

func TestTooManyFailuresAborts(t *testing.T) {
	t.Parallel()
	h := newHarness(testProfile(profile.ModePersistent))
	h.cfg.MaxConsecutiveFailures = 3
	h.tr.openErr = func(int) error { return errors.New("unreachable") }
	st, err := Run(context.Background(), h.cfg)
	if !errors.Is(err, ErrTooManyFailures) || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("err = %v", err)
	}
	if st.Failures != 3 || st.Beacons != 0 {
		t.Errorf("Stats = %+v", st)
	}
}

func TestRequestFailureClosesSessionAndRecordsError(t *testing.T) {
	t.Parallel()
	h := newHarness(testProfile(profile.ModePersistent))
	h.cfg.MaxBeacons = 3
	h.tr.doErr = func(n int) error {
		if n == 2 {
			return errors.New("stream reset")
		}
		return nil
	}
	st := h.run(t)
	if st != (Stats{Sessions: 2, Beacons: 3, Failures: 1}) {
		t.Fatalf("Stats = %+v", st)
	}
	sessions := h.rec.kind(groundtruth.KindSession)
	if len(sessions) != 2 || sessions[0].Error != "stream reset" || sessions[0].Beacons != 1 || sessions[1].Beacons != 2 {
		t.Fatalf("sessions = %+v", sessions)
	}
	var failed int
	for _, b := range h.rec.kind(groundtruth.KindBeacon) {
		if b.Error != "" {
			failed++
			if b.Seq != 2 {
				t.Errorf("failed beacon seq = %d", b.Seq)
			}
		}
	}
	if failed != 1 {
		t.Errorf("failed beacon records = %d", failed)
	}
}

type staticHandler struct {
	code int
	body string
}

func (s staticHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(s.code)
	_, _ = w.Write([]byte(s.body))
}

func TestBadResponsesCountAsFailures(t *testing.T) {
	t.Parallel()
	tests := map[string]staticHandler{
		"server error": {code: 500, body: "oops"},
		"not an ack":   {code: 200, body: "<html>"},
		"wrong seq":    {code: 200, body: `{"sim":"quic-research/beaconsim","run":"run-test","seq":99,"received":"2026-11-23T12:00:00Z"}`},
	}
	for name, handler := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(testProfile(profile.ModePersistent))
			h.tr.h = handler
			h.cfg.MaxConsecutiveFailures = 2
			st, err := Run(context.Background(), h.cfg)
			if !errors.Is(err, ErrTooManyFailures) || st.Beacons != 0 {
				t.Fatalf("Stats = %+v, err = %v", st, err)
			}
		})
	}
}

func TestPermanentFailuresAreNotRetried(t *testing.T) {
	t.Parallel()
	h := newHarness(testProfile(profile.ModePersistent))
	forbidden := errors.New("not a lab address")
	h.tr.openErr = func(int) error { return Permanent(forbidden) }
	st, err := Run(context.Background(), h.cfg)
	if !errors.Is(err, ErrPermanent) || !errors.Is(err, forbidden) {
		t.Fatalf("err = %v", err)
	}
	if h.tr.opens != 1 || st.Failures != 1 || len(h.clock.sleeps) != 0 {
		t.Errorf("permanent failure was retried: opens=%d stats=%+v sleeps=%v", h.tr.opens, st, h.clock.sleeps)
	}
	if Permanent(nil) != nil {
		t.Error("Permanent(nil) must be nil")
	}
}

func TestRecorderFailureIsFatal(t *testing.T) {
	t.Parallel()
	for _, kind := range []groundtruth.Kind{groundtruth.KindBeacon, groundtruth.KindSession} {
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()
			h := newHarness(testProfile(profile.ModePerBeacon))
			h.cfg.MaxBeacons = 10
			h.rec.err = func(r groundtruth.Record) error {
				if r.Kind == kind {
					return errors.New("disk full")
				}
				return nil
			}
			st, err := Run(context.Background(), h.cfg)
			if !errors.Is(err, ErrRecorder) || !strings.Contains(err.Error(), "disk full") {
				t.Fatalf("err = %v", err)
			}
			if st.Beacons > 1 {
				t.Errorf("run continued after a recorder failure: %+v", st)
			}
		})
	}
}

func TestCancellationIsGracefulAndRecordsOpenSession(t *testing.T) {
	t.Parallel()
	h := newHarness(testProfile(profile.ModePersistent))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.clock.onSleep = func(n int) {
		if n == 3 {
			cancel()
		}
	}
	h.cfg.Clock = h.clock
	st, err := Run(ctx, h.cfg)
	if err != nil {
		t.Fatalf("cancellation should not be an error, got %v", err)
	}
	if st.Beacons != 3 {
		t.Errorf("Beacons = %d", st.Beacons)
	}
	sessions := h.rec.kind(groundtruth.KindSession)
	if len(sessions) != 1 || sessions[0].Beacons != 3 {
		t.Fatalf("open session not recorded on cancel: %+v", sessions)
	}
	if h.tr.closes != 1 {
		t.Errorf("closes = %d", h.tr.closes)
	}
}

func TestAlreadyCancelledContext(t *testing.T) {
	t.Parallel()
	h := newHarness(testProfile(profile.ModePersistent))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	st, err := Run(ctx, h.cfg)
	if err != nil || st != (Stats{}) || h.tr.opens != 0 {
		t.Fatalf("Stats = %+v, err = %v, opens = %d", st, err, h.tr.opens)
	}
}

func TestCloseErrorsAreNotFatal(t *testing.T) {
	t.Parallel()
	h := newHarness(testProfile(profile.ModePerBeacon))
	h.cfg.MaxBeacons = 3
	h.tr.closeErr = errors.New("already closed")
	if st := h.run(t); st.Beacons != 3 || st.Failures != 0 {
		t.Fatalf("Stats = %+v", st)
	}
}

func TestDeterministicForSeed(t *testing.T) {
	t.Parallel()
	shape := func(seed uint64) ([]time.Duration, []int) {
		h := newHarness(testProfile(profile.ModePersistent))
		h.cfg.Profile.Schedule.Jitter = 0.5
		h.cfg.Seed = seed
		h.cfg.MaxBeacons = 10
		h.run(t)
		sizes := make([]int, len(h.tr.reqs))
		for i, r := range h.tr.reqs {
			sizes[i] = len(r.Body)
		}
		return h.clock.sleeps, sizes
	}
	s1, b1 := shape(7)
	s2, b2 := shape(7)
	s3, _ := shape(8)
	if fmt.Sprint(s1) != fmt.Sprint(s2) || fmt.Sprint(b1) != fmt.Sprint(b2) {
		t.Fatal("same seed produced different runs")
	}
	if fmt.Sprint(s1) == fmt.Sprint(s3) {
		t.Fatal("different seeds produced identical timing")
	}
}

func TestConfigValidation(t *testing.T) {
	t.Parallel()
	base := newHarness(testProfile(profile.ModePersistent)).cfg
	tests := map[string]func(*Config){
		"invalid profile":   func(c *Config) { c.Profile.Name = "" },
		"no run id":         func(c *Config) { c.RunID = "" },
		"bad run id":        func(c *Config) { c.RunID = "has space" },
		"no transport":      func(c *Config) { c.Transport = nil },
		"negative duration": func(c *Config) { c.Duration = -1 },
		"negative failures": func(c *Config) { c.MaxConsecutiveFailures = -1 },
		"negative backoff":  func(c *Config) { c.RetryBackoff = -1 },
	}
	for name, mut := range tests {
		cfg := base
		mut(&cfg)
		if _, err := Run(context.Background(), cfg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestDefaultsApply(t *testing.T) {
	t.Parallel()
	r, err := newRunner(Config{Profile: testProfile(profile.ModePersistent), RunID: "r", Transport: &labTransport{}})
	if err != nil {
		t.Fatal(err)
	}
	if r.cfg.MaxConsecutiveFailures != DefaultMaxConsecutiveFailures || r.cfg.RetryBackoff != DefaultRetryBackoff {
		t.Errorf("defaults not applied: %+v", r.cfg)
	}
	if _, ok := r.cfg.Clock.(RealClock); !ok || r.cfg.Recorder == nil || r.cfg.Logger == nil {
		t.Errorf("nil dependencies not defaulted: %+v", r.cfg)
	}
}

func TestRealClock(t *testing.T) {
	t.Parallel()
	c := RealClock{}
	start := c.Now()
	if err := c.Sleep(context.Background(), 5*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 5*time.Millisecond {
		t.Error("Sleep returned early")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Sleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sleep on canceled ctx = %v", err)
	}
}
