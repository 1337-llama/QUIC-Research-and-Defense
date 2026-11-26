// Package quictransport implements beacon.Transport over HTTP/3 using
// quic-go, the QUIC library used by most QUIC C2 seen in the wild. Using the
// same library keeps the simulator's handshake fingerprints realistic.
package quictransport

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

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/beacon"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/payload"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/profile"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/safety"
)

// DefaultHandshakeTimeout bounds connection setup.
const DefaultHandshakeTimeout = 10 * time.Second

// ErrSessionClosed is returned by a session after Close.
var ErrSessionClosed = errors.New("quictransport: session closed")

// Config configures a Transport.
type Config struct {
	// Target is the lab server's host:port.
	Target string
	// ServerName is the TLS server name (SNI). Defaults to Target's host.
	ServerName string
	// RootCAs must contain the lab server's certificate. Verification is
	// never disabled.
	RootCAs *x509.CertPool
	// KeyLog, if set, receives TLS secrets in NSS key log format so
	// analysts can decrypt captures in Wireshark.
	KeyLog io.Writer
	// QUIC holds the transport settings to advertise.
	QUIC profile.QUIC
	// Policy restricts destinations to lab addresses unless it allows
	// public ones.
	Policy safety.Policy
	// Resolver resolves Target's host. Defaults to net.DefaultResolver.
	Resolver safety.Resolver
	// HandshakeTimeout defaults to DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
}

// Transport opens HTTP/3 sessions, each on its own UDP socket and QUIC
// connection.
type Transport struct {
	cfg       Config
	tlsConf   *tls.Config
	quicConf  *quic.Config
	authority string
}

var _ beacon.Transport = (*Transport)(nil)

// New validates cfg and returns a Transport.
func New(cfg Config) (*Transport, error) {
	host, port, err := net.SplitHostPort(cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("quictransport: target %q: %w", cfg.Target, err)
	}
	if cfg.RootCAs == nil {
		return nil, errors.New("quictransport: RootCAs is required; certificate verification is never disabled")
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
	tlsConf := &tls.Config{
		ServerName: cfg.ServerName,
		RootCAs:    cfg.RootCAs,
		NextProtos: []string{http3.NextProtoH3},
		MinVersion: tls.VersionTLS13,
	}
	if cfg.KeyLog != nil {
		tlsConf.KeyLogWriter = &lockedWriter{w: cfg.KeyLog}
	}
	return &Transport{
		cfg:       cfg,
		tlsConf:   tlsConf,
		quicConf:  QUICConfig(cfg.QUIC, cfg.HandshakeTimeout),
		authority: net.JoinHostPort(cfg.ServerName, port),
	}, nil
}

// QUICConfig maps profile settings onto a quic-go configuration. Zero
// profile values keep quic-go's defaults.
func QUICConfig(p profile.QUIC, handshakeTimeout time.Duration) *quic.Config {
	c := &quic.Config{
		HandshakeIdleTimeout:           handshakeTimeout,
		MaxIdleTimeout:                 p.MaxIdleTimeout.Std(),
		KeepAlivePeriod:                p.KeepAlivePeriod.Std(),
		InitialStreamReceiveWindow:     p.InitialStreamReceiveWindow,
		InitialConnectionReceiveWindow: p.InitialConnectionReceiveWindow,
		EnableDatagrams:                p.EnableDatagrams,
	}
	if p.HandshakeIdleTimeout > 0 {
		c.HandshakeIdleTimeout = p.HandshakeIdleTimeout.Std()
	}
	return c
}

// Open dials a new QUIC connection on a fresh UDP socket.
func (t *Transport) Open(ctx context.Context) (beacon.Session, error) {
	addrs, err := t.cfg.Policy.Resolve(ctx, t.cfg.Resolver, t.cfg.Target)
	if errors.Is(err, safety.ErrNotLab) {
		return nil, beacon.Permanent(err)
	}
	if err != nil {
		return nil, err
	}
	remote := addrs[0]
	local, err := sourceAddrFor(remote)
	if err != nil {
		return nil, err
	}
	// Binding to the concrete source address (not 0.0.0.0) lets ground
	// truth record exactly the 4-tuple a sensor will log.
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)))
	if err != nil {
		return nil, fmt.Errorf("quictransport: binding UDP socket: %w", err)
	}
	qt := &quic.Transport{Conn: pc}

	dctx, cancel := context.WithTimeout(ctx, t.cfg.HandshakeTimeout)
	defer cancel()
	// Dial (not DialEarly): the handshake, including certificate
	// verification, completes before the session is handed out.
	conn, err := qt.Dial(dctx, net.UDPAddrFromAddrPort(remote), t.tlsConf.Clone(), t.quicConf.Clone())
	if err != nil {
		_ = qt.Close()
		_ = pc.Close()
		return nil, fmt.Errorf("quictransport: dialing %s: %w", remote, err)
	}

	la, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = conn.CloseWithError(0, "")
		_ = qt.Close()
		_ = pc.Close()
		return nil, fmt.Errorf("quictransport: unexpected local address type %T", pc.LocalAddr())
	}
	s := &session{
		conn:    conn,
		qt:      qt,
		pc:      pc,
		baseURL: "https://" + t.authority,
		info: beacon.SessionInfo{
			Local:  netip.AddrPortFrom(local, la.AddrPort().Port()),
			Remote: remote,
		},
	}
	// Run HTTP/3 over the connection we already dialed, so every request in
	// this session shares one QUIC connection and one UDP socket.
	s.h3 = &http3.Transport{}
	s.client = &http.Client{Transport: s.h3.NewClientConn(conn)}
	return s, nil
}

// sourceAddrFor asks the kernel which local address routes to remote. No
// packets are sent: connecting a UDP socket only consults the routing table.
func sourceAddrFor(remote netip.AddrPort) (netip.Addr, error) {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(remote))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("quictransport: no route to %s: %w", remote, err)
	}
	defer func() { _ = c.Close() }()
	la, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, fmt.Errorf("quictransport: unexpected local address type %T", c.LocalAddr())
	}
	return la.AddrPort().Addr().Unmap(), nil
}

type session struct {
	conn    *quic.Conn
	qt      *quic.Transport
	pc      *net.UDPConn
	h3      *http3.Transport
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
		return beacon.Response{}, fmt.Errorf("quictransport: building request: %w", err)
	}
	if req.UserAgent != "" {
		hreq.Header.Set("User-Agent", req.UserAgent)
	}
	if len(req.Body) > 0 {
		hreq.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(hreq)
	if err != nil {
		return beacon.Response{}, fmt.Errorf("quictransport: %s %s: %w", req.Method, req.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, payload.MaxBodyBytes+1))
	if err != nil {
		return beacon.Response{}, fmt.Errorf("quictransport: reading response: %w", err)
	}
	if len(data) > payload.MaxBodyBytes {
		return beacon.Response{}, fmt.Errorf("quictransport: response exceeds %d bytes", payload.MaxBodyBytes)
	}
	return beacon.Response{StatusCode: resp.StatusCode, Body: data}, nil
}

// Close tears down the HTTP/3 layer, the QUIC connection and the socket.
// It is idempotent.
func (s *session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	errs := []error{
		s.h3.Close(),
		s.conn.CloseWithError(0, "beaconsim session complete"),
		s.qt.Close(),
	}
	if err := s.pc.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
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
