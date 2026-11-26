package tlstransport_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/beacon"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/certs"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/labserver"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/payload"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/safety"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/tlstransport"
)

// observed records how each request reached the server.
type observed struct {
	mu      sync.Mutex
	protos  []int
	remotes []string
}

func (o *observed) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.protos = append(o.protos, r.ProtoMajor)
		o.remotes = append(o.remotes, r.RemoteAddr)
		o.mu.Unlock()
		h.ServeHTTP(w, r)
	})
}

type server struct {
	addr string
	pool *x509.CertPool
	obs  *observed
	srv  *http.Server

	mu    sync.Mutex
	conns []net.Conn
}

func (s *server) closeClientConns() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		_ = c.Close()
	}
}

// startServer serves the lab handler over TLS on loopback. mutate may change
// the server's TLS settings before it starts.
func startServer(t *testing.T, h http.Handler, mutate func(*http.Server)) *server {
	t.Helper()
	g, err := certs.SelfSigned([]string{"c2-tcp", "127.0.0.1"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := certs.PoolFromPEM(g.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if h == nil {
		h = labserver.New(nil, nil)
	}
	s := &server{pool: pool, obs: &observed{}}
	s.srv = labserver.NewTLSServer(s.obs.wrap(h), g.TLS)
	s.srv.ErrorLog = log.New(io.Discard, "", 0)
	s.srv.ConnState = func(c net.Conn, st http.ConnState) {
		if st == http.StateNew {
			s.mu.Lock()
			s.conns = append(s.conns, c)
			s.mu.Unlock()
		}
	}
	if mutate != nil {
		mutate(s.srv)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.addr = ln.Addr().String()
	go func() { _ = s.srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = s.srv.Close() })
	return s
}

func newTransport(t *testing.T, s *server, mutate func(*tlstransport.Config)) *tlstransport.Transport {
	t.Helper()
	cfg := tlstransport.Config{Target: s.addr, ServerName: "c2-tcp", RootCAs: s.pool, HandshakeTimeout: 5 * time.Second}
	if mutate != nil {
		mutate(&cfg)
	}
	tr, err := tlstransport.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func beaconReq(t *testing.T, seq uint64) beacon.Request {
	t.Helper()
	_, body, err := payload.NewBeacon("tls-test", seq, time.Now(), 256, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return beacon.Request{Method: http.MethodPost, Path: "/api/v1/beacon", UserAgent: "lab-test", Body: body}
}

func TestBeaconsShareOneHTTP2Connection(t *testing.T) {
	t.Parallel()
	s := startServer(t, nil, nil)
	tr := newTransport(t, s, nil)
	sess, err := tr.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()

	info := sess.Info()
	if info.Transport != "tcp" || info.Remote.String() != s.addr || !info.Local.Addr().IsLoopback() || info.Local.Port() == 0 {
		t.Fatalf("Info = %+v", info)
	}
	for seq := uint64(1); seq <= 3; seq++ {
		resp, err := sess.Do(context.Background(), beaconReq(t, seq))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK || !bytes.Contains(resp.Body, []byte(`"seq":`)) {
			t.Fatalf("seq %d: %d %s", seq, resp.StatusCode, resp.Body)
		}
	}
	resp, err := sess.Do(context.Background(), beacon.Request{Method: http.MethodGet, Path: "/"})
	if err != nil || resp.StatusCode != http.StatusOK || !strings.Contains(string(resp.Body), "lab server") {
		t.Fatalf("GET: %v %+v", err, resp)
	}

	s.obs.mu.Lock()
	defer s.obs.mu.Unlock()
	for i, p := range s.obs.protos {
		if p != 2 {
			t.Errorf("request %d used HTTP/%d, want HTTP/2", i, p)
		}
		if s.obs.remotes[i] != info.Local.String() {
			t.Errorf("request %d came from %s, want the session's %s", i, s.obs.remotes[i], info.Local)
		}
	}
	if len(s.obs.protos) != 4 {
		t.Errorf("server saw %d requests, want 4", len(s.obs.protos))
	}
}

func TestSessionNeverRedials(t *testing.T) {
	t.Parallel()
	s := startServer(t, nil, nil)
	sess, err := newTransport(t, s, nil).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	if _, err := sess.Do(context.Background(), beaconReq(t, 1)); err != nil {
		t.Fatal(err)
	}
	s.closeClientConns()
	// Ground truth records one 4-tuple per session, so once the server drops
	// the connection the session must fail rather than quietly reconnect.
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err = sess.Do(context.Background(), beaconReq(t, 2))
		if err != nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err == nil {
		t.Fatal("Do succeeded after the server closed the session's connection")
	}
	s.obs.mu.Lock()
	defer s.obs.mu.Unlock()
	if n := len(s.obs.remotes); n != 1 {
		t.Errorf("server saw %d requests, want 1", n)
	}
}

func TestKeyLogIsWritten(t *testing.T) {
	t.Parallel()
	s := startServer(t, nil, nil)
	var buf bytes.Buffer
	sess, err := newTransport(t, s, func(c *tlstransport.Config) { c.KeyLog = &buf }).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = sess.Close()
	if !strings.Contains(buf.String(), "CLIENT_TRAFFIC_SECRET_0") && !strings.Contains(buf.String(), "CLIENT_RANDOM") {
		t.Fatalf("key log missing secrets: %q", buf.String())
	}
}

func TestRefusesPublicTargets(t *testing.T) {
	t.Parallel()
	tr, err := tlstransport.New(tlstransport.Config{Target: "203.0.113.7:443", RootCAs: x509.NewCertPool()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tr.Open(context.Background())
	if !errors.Is(err, safety.ErrNotLab) || !errors.Is(err, beacon.ErrPermanent) {
		t.Fatalf("err = %v, want permanent ErrNotLab", err)
	}
}

func TestUntrustedCertificateFails(t *testing.T) {
	t.Parallel()
	s := startServer(t, nil, nil)
	_, err := newTransport(t, s, func(c *tlstransport.Config) { c.RootCAs = x509.NewCertPool() }).Open(context.Background())
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("err = %v, want x509.UnknownAuthorityError", err)
	}
	if errors.Is(err, beacon.ErrPermanent) {
		t.Error("a handshake failure should be retryable")
	}
}

func TestRequiresHTTP2(t *testing.T) {
	t.Parallel()
	s := startServer(t, nil, func(srv *http.Server) {
		srv.TLSConfig.NextProtos = []string{"http/1.1"}
		srv.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){} // disable h2
	})
	// The server shares no protocol with a client that offers only h2, so
	// the handshake fails instead of degrading to HTTP/1.1.
	if _, err := newTransport(t, s, nil).Open(context.Background()); err == nil {
		t.Fatal("Open succeeded without h2")
	}
}

func TestNoALPNIsPermanent(t *testing.T) {
	t.Parallel()
	// A bare TLS server that ignores ALPN completes the handshake with no
	// negotiated protocol; that target can never work, so it is permanent.
	g, err := certs.SelfSigned([]string{"c2-tcp"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := certs.PoolFromPEM(g.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{g.TLS}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.(*tls.Conn).Handshake()
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	tr, err := tlstransport.New(tlstransport.Config{Target: ln.Addr().String(), ServerName: "c2-tcp", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tr.Open(context.Background())
	if !errors.Is(err, tlstransport.ErrNotHTTP2) || !errors.Is(err, beacon.ErrPermanent) {
		t.Fatalf("err = %v, want permanent ErrNotHTTP2", err)
	}
}

func TestDialFailure(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	tr, err := tlstransport.New(tlstransport.Config{Target: addr, RootCAs: x509.NewCertPool()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Open(context.Background()); err == nil || errors.Is(err, beacon.ErrPermanent) {
		t.Fatalf("err = %v, want a retryable dial error", err)
	}
}

func TestOversizedResponse(t *testing.T) {
	t.Parallel()
	big := bytes.Repeat([]byte("x"), payload.MaxBodyBytes+1)
	s := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(big) }), nil)
	sess, err := newTransport(t, s, nil).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	if _, err := sess.Do(context.Background(), beacon.Request{Method: http.MethodGet, Path: "/"}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want size error", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	t.Parallel()
	s := startServer(t, nil, nil)
	sess, err := newTransport(t, s, nil).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := sess.Do(context.Background(), beaconReq(t, 1)); !errors.Is(err, tlstransport.ErrSessionClosed) {
		t.Fatalf("Do after Close = %v", err)
	}
}

func TestBadRequest(t *testing.T) {
	t.Parallel()
	s := startServer(t, nil, nil)
	sess, err := newTransport(t, s, nil).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	if _, err := sess.Do(context.Background(), beacon.Request{Method: "BAD METHOD", Path: "/"}); err == nil {
		t.Fatal("invalid method accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sess.Do(ctx, beaconReq(t, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Do = %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	t.Parallel()
	for name, cfg := range map[string]tlstransport.Config{
		"no port":    {Target: "c2-tcp", RootCAs: x509.NewCertPool()},
		"no rootCAs": {Target: "c2-tcp:443"},
	} {
		if _, err := tlstransport.New(cfg); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
}
