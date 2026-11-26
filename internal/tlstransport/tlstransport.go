// Package tlstransport implements beacon.Transport over HTTP/2 on TLS/TCP.
//
// Real QUIC implants commonly fall back to HTTPS over TCP when a network
// blocks UDP/443, because browsers do the same. The lab uses this transport
// to show defenders that blocking QUIC moves the beacon rather than stopping
// it, so the TCP-side detections must still fire. Like the QUIC transport,
// it only dials lab addresses unless the policy says otherwise, and it never
// disables certificate verification.
package tlstransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/beacon"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/payload"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/safety"
)

// DefaultHandshakeTimeout bounds TCP connect plus the TLS handshake.
const DefaultHandshakeTimeout = 10 * time.Second

// ErrSessionClosed is returned by a session after Close.
var ErrSessionClosed = errors.New("tlstransport: session closed")

// ErrNotHTTP2 is returned when the server does not negotiate h2. The lab
// server always offers it, so this indicates a misconfigured target.
var ErrNotHTTP2 = errors.New("tlstransport: server did not negotiate h2")

// Config configures a Transport.
type Config struct {
	// Target is the lab server's host:port.
	Target string
	// ServerName is the TLS server name (SNI). Defaults to Target's host.
	ServerName string
	// RootCAs must contain the lab server's certificate.
	RootCAs *x509.CertPool
	// KeyLog, if set, receives TLS secrets in NSS key log format.
	KeyLog io.Writer
	// Policy restricts destinations to lab addresses.
	Policy safety.Policy
	// Resolver resolves Target's host. Defaults to net.DefaultResolver.
	Resolver safety.Resolver
	// HandshakeTimeout defaults to DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
	// Dialer dials TCP. Defaults to a net.Dialer; tests may replace it.
	Dialer interface {
		DialContext(ctx context.Context, network, address string) (net.Conn, error)
	}
}

// Transport opens HTTP/2 sessions, each on its own TCP connection.
type Transport struct {
	cfg       Config
	tlsConf   *tls.Config
	authority string
}

var _ beacon.Transport = (*Transport)(nil)

// New validates cfg and returns a Transport.
func New(cfg Config) (*Transport, error) {
	host, port, err := net.SplitHostPort(cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("tlstransport: target %q: %w", cfg.Target, err)
	}
	if cfg.RootCAs == nil {
		return nil, errors.New("tlstransport: RootCAs is required; certificate verification is never disabled")
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if cfg.Dialer == nil {
		cfg.Dialer = &net.Dialer{}
	}
	tlsConf := &tls.Config{
		ServerName: cfg.ServerName,
		RootCAs:    cfg.RootCAs,
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS12,
	}
	if cfg.KeyLog != nil {
		tlsConf.KeyLogWriter = &lockedWriter{w: cfg.KeyLog}
	}
	return &Transport{
		cfg:       cfg,
		tlsConf:   tlsConf,
		authority: net.JoinHostPort(cfg.ServerName, port),
	}, nil
}

// Open dials TCP, completes the TLS handshake (including certificate
// verification) and returns a session that sends every request over that
// one connection.
func (t *Transport) Open(ctx context.Context) (beacon.Session, error) {
	addrs, err := t.cfg.Policy.Resolve(ctx, t.cfg.Resolver, t.cfg.Target)
	if errors.Is(err, safety.ErrNotLab) {
		return nil, beacon.Permanent(err)
	}
	if err != nil {
		return nil, err
	}
	remote := addrs[0]

	dctx, cancel := context.WithTimeout(ctx, t.cfg.HandshakeTimeout)
	defer cancel()
	raw, err := t.cfg.Dialer.DialContext(dctx, "tcp", remote.String())
	if err != nil {
		return nil, fmt.Errorf("tlstransport: dialing %s: %w", remote, err)
	}
	conn := tls.Client(raw, t.tlsConf.Clone())
	if err := conn.HandshakeContext(dctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("tlstransport: handshake with %s: %w", remote, err)
	}
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = conn.Close()
		return nil, beacon.Permanent(ErrNotHTTP2)
	}
	local, ok := addrPort(raw.LocalAddr())
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("tlstransport: unexpected local address type %T", raw.LocalAddr())
	}

	s := &session{
		conn:    conn,
		baseURL: "https://" + t.authority,
		info:    beacon.SessionInfo{Local: local, Remote: remote, Transport: "tcp"},
	}
	// The HTTP transport may only ever use the connection dialed above, so
	// a session is exactly one TCP flow, as ground truth records it.
	var once sync.Once
	s.rt = &http.Transport{
		ForceAttemptHTTP2:   true,
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			var c net.Conn
			once.Do(func() { c = conn })
			if c == nil {
				return nil, errSessionConnUsed
			}
			return c, nil
		},
	}
	s.client = &http.Client{Transport: s.rt}
	return s, nil
}

var errSessionConnUsed = errors.New("tlstransport: session connection is gone; open a new session")

func addrPort(a net.Addr) (netip.AddrPort, bool) {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap := ta.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

type session struct {
	conn    *tls.Conn
	rt      *http.Transport
	client  *http.Client
	info    beacon.SessionInfo
	baseURL string

	mu     sync.Mutex
	closed bool
}

func (s *session) Info() beacon.SessionInfo { return s.info }

func (s *session) Do(ctx context.Context, req beacon.Request) (beacon.Response, error) {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return beacon.Response{}, ErrSessionClosed
	}
	var body io.Reader = http.NoBody
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	hreq, err := http.NewRequestWithContext(ctx, req.Method, s.baseURL+req.Path, body)
	if err != nil {
		return beacon.Response{}, fmt.Errorf("tlstransport: building request: %w", err)
	}
	if req.UserAgent != "" {
		hreq.Header.Set("User-Agent", req.UserAgent)
	}
	if len(req.Body) > 0 {
		hreq.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(hreq)
	if err != nil {
		return beacon.Response{}, fmt.Errorf("tlstransport: %s %s: %w", req.Method, req.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, payload.MaxBodyBytes+1))
	if err != nil {
		return beacon.Response{}, fmt.Errorf("tlstransport: reading response: %w", err)
	}
	if len(data) > payload.MaxBodyBytes {
		return beacon.Response{}, fmt.Errorf("tlstransport: response exceeds %d bytes", payload.MaxBodyBytes)
	}
	return beacon.Response{StatusCode: resp.StatusCode, Body: data}, nil
}

// Close tears down the HTTP/2 layer and the TCP connection. It is
// idempotent.
func (s *session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	s.rt.CloseIdleConnections()
	if err := s.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// lockedWriter serializes key-log writes from concurrent handshakes.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
