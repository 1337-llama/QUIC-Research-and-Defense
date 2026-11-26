package quictransport_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/beacon"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/certs"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/groundtruth"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/profile"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/safety"
	"github.com/1337-llama/QUIC-Research-and-Defense/lab/internal/labtest"
	"github.com/1337-llama/QUIC-Research-and-Defense/lab/internal/quictransport"
)

type recorder struct {
	mu   sync.Mutex
	recs []groundtruth.Record
}

func (r *recorder) Record(rec groundtruth.Record) error {
	if err := rec.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = append(r.recs, rec)
	return nil
}

func (r *recorder) sessions() []groundtruth.Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []groundtruth.Record
	for _, x := range r.recs {
		if x.Kind == groundtruth.KindSession {
			out = append(out, x)
		}
	}
	return out
}

func fastProfile(t *testing.T, name string) profile.Profile {
	t.Helper()
	p, err := profile.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	p.Schedule.Interval = profile.Duration(20 * time.Millisecond)
	if p.Schedule.Distribution == profile.DistJitter {
		p.Schedule.Jitter = 0
	}
	return p
}

func newTransport(t *testing.T, srv *labtest.Server, p profile.Profile) *quictransport.Transport {
	t.Helper()
	tr, err := quictransport.New(quictransport.Config{
		Target: srv.Addr, ServerName: "localhost", RootCAs: srv.Pool, QUIC: p.QUIC,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func runProfile(t *testing.T, srv *labtest.Server, p profile.Profile, beacons uint64) (beacon.Stats, *recorder) {
	t.Helper()
	rec := &recorder{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := beacon.Run(ctx, beacon.Config{
		Profile: p, RunID: "it-" + p.Name, Seed: 1, Transport: newTransport(t, srv, p),
		Recorder: rec, MaxBeacons: beacons, MaxConsecutiveFailures: 2,
	})
	if err != nil {
		t.Fatalf("Run(%s): %v", p.Name, err)
	}
	return st, rec
}

func TestPersistentProfileSharesOneConnection(t *testing.T) {
	t.Parallel()
	srv := labtest.Start(t)
	st, rec := runProfile(t, srv, fastProfile(t, "merlin-like"), 5)
	if st.Sessions != 1 || st.Beacons != 5 || st.Failures != 0 {
		t.Fatalf("Stats = %+v", st)
	}
	if got := srv.Handler.Stats().Beacons; got != 5 {
		t.Fatalf("server acknowledged %d beacons", got)
	}
	sessions := rec.sessions()
	if len(sessions) != 1 {
		t.Fatalf("sessions = %+v", sessions)
	}
	// Ground truth must name exactly the 4-tuple the server (and a sensor)
	// sees, or scoring cannot match alerts to sessions.
	want := sessions[0].Local.String()
	for i, r := range srv.Remotes() {
		if r != want {
			t.Errorf("request %d came from %s, ground truth says %s", i, r, want)
		}
	}
	for _, p := range srv.Protos() {
		if p != "HTTP/3.0" {
			t.Errorf("request protocol = %q, want HTTP/3.0", p)
		}
	}
	if ua := srv.UserAgents()[0]; ua != "beaconsim/merlin-like" {
		t.Errorf("User-Agent = %q", ua)
	}
}

func TestPerBeaconProfileUsesDistinctSockets(t *testing.T) {
	t.Parallel()
	srv := labtest.Start(t)
	st, rec := runProfile(t, srv, fastProfile(t, "quicagent-like"), 3)
	if st.Sessions != 3 || st.Beacons != 3 {
		t.Fatalf("Stats = %+v", st)
	}
	remotes := srv.Remotes()
	sessions := rec.sessions()
	seen := map[string]bool{}
	for i, s := range sessions {
		if s.Local.String() != remotes[i] {
			t.Errorf("session %d: ground truth %s, server saw %s", i+1, s.Local, remotes[i])
		}
		seen[remotes[i]] = true
	}
	if len(seen) != 3 {
		t.Errorf("expected 3 distinct client sockets, got %v", remotes)
	}
}

func TestGetProfile(t *testing.T) {
	t.Parallel()
	srv := labtest.Start(t)
	st, _ := runProfile(t, srv, fastProfile(t, "browser-like"), 2)
	if st.Beacons != 2 {
		t.Fatalf("Stats = %+v", st)
	}
	if got := srv.Handler.Stats(); got.Pages != 2 || got.Beacons != 0 {
		t.Errorf("server stats = %+v", got)
	}
}

func TestKeyLogIsWritten(t *testing.T) {
	t.Parallel()
	srv := labtest.Start(t)
	p := fastProfile(t, "merlin-like")
	var keys bytes.Buffer
	tr, err := quictransport.New(quictransport.Config{Target: srv.Addr, ServerName: "localhost", RootCAs: srv.Pool, KeyLog: &keys, QUIC: p.QUIC})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := beacon.Run(context.Background(), beacon.Config{Profile: p, RunID: "k", Transport: tr, MaxBeacons: 1}); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0"} {
		if !strings.Contains(keys.String(), label) {
			t.Errorf("key log missing %s", label)
		}
	}
}

func TestRefusesPublicTargets(t *testing.T) {
	t.Parallel()
	pool, _ := certs.PoolFromPEM(labtest.Start(t).CertPEM)
	tr, err := quictransport.New(quictransport.Config{Target: "8.8.8.8:443", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Open(context.Background()); !errors.Is(err, safety.ErrNotLab) {
		t.Fatalf("Open(8.8.8.8) err = %v, want ErrNotLab", err)
	}
}

func TestUntrustedCertificateFails(t *testing.T) {
	t.Parallel()
	srv := labtest.Start(t)
	other, err := certs.SelfSigned([]string{"localhost"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := certs.PoolFromPEM(other.CertPEM)
	tr, err := quictransport.New(quictransport.Config{Target: srv.Addr, ServerName: "localhost", RootCAs: pool, HandshakeTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	s, err := tr.Open(context.Background())
	if err == nil {
		_, err = s.Do(context.Background(), beacon.Request{Method: "GET", Path: "/"})
		_ = s.Close()
	}
	if err == nil {
		t.Fatal("connection to a server with an untrusted certificate succeeded")
	}
}

func TestHandshakeTimeout(t *testing.T) {
	t.Parallel()
	// A bound socket that never answers.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	pool, _ := certs.PoolFromPEM(labtest.Start(t).CertPEM)
	tr, err := quictransport.New(quictransport.Config{Target: pc.LocalAddr().String(), ServerName: "localhost", RootCAs: pool, HandshakeTimeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := tr.Open(context.Background()); err == nil {
		t.Fatal("Open succeeded against a silent peer")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("handshake timeout took %s", took)
	}
}

func TestSessionLifecycle(t *testing.T) {
	t.Parallel()
	srv := labtest.Start(t)
	tr := newTransport(t, srv, fastProfile(t, "browser-like"))
	s, err := tr.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	info := s.Info()
	if !info.Local.Addr().IsLoopback() || info.Local.Port() == 0 || info.Remote.String() != srv.Addr {
		t.Errorf("Info = %+v", info)
	}
	resp, err := s.Do(context.Background(), beacon.Request{Method: "GET", Path: "/", UserAgent: "ua"})
	if err != nil || resp.StatusCode != http.StatusOK || !strings.Contains(string(resp.Body), "lab server") {
		t.Fatalf("Do = %+v, %v", resp, err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if _, err := s.Do(context.Background(), beacon.Request{Method: "GET", Path: "/"}); !errors.Is(err, quictransport.ErrSessionClosed) {
		t.Errorf("Do after Close = %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	t.Parallel()
	pool, _ := certs.PoolFromPEM(labtest.Start(t).CertPEM)
	if _, err := quictransport.New(quictransport.Config{Target: "no-port", RootCAs: pool}); err == nil {
		t.Error("target without port accepted")
	}
	if _, err := quictransport.New(quictransport.Config{Target: "127.0.0.1:443"}); err == nil {
		t.Error("missing RootCAs accepted")
	}
}

func TestQUICConfig(t *testing.T) {
	t.Parallel()
	p := profile.QUIC{
		MaxIdleTimeout: profile.Duration(30 * time.Second), KeepAlivePeriod: profile.Duration(15 * time.Second),
		InitialStreamReceiveWindow: 1 << 20, InitialConnectionReceiveWindow: 2 << 20, EnableDatagrams: true,
	}
	c := quictransport.QUICConfig(p, 7*time.Second)
	if c.MaxIdleTimeout != 30*time.Second || c.KeepAlivePeriod != 15*time.Second || c.HandshakeIdleTimeout != 7*time.Second ||
		c.InitialStreamReceiveWindow != 1<<20 || c.InitialConnectionReceiveWindow != 2<<20 || !c.EnableDatagrams {
		t.Errorf("QUICConfig = %+v", c)
	}
	p.HandshakeIdleTimeout = profile.Duration(2 * time.Second)
	if c := quictransport.QUICConfig(p, 7*time.Second); c.HandshakeIdleTimeout != 2*time.Second {
		t.Errorf("profile handshake timeout not applied: %s", c.HandshakeIdleTimeout)
	}
}
