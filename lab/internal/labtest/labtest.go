// Package labtest starts real HTTP/3 lab servers for integration tests.
package labtest

import (
	"context"
	"crypto/x509"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/1337-llama/quic_research/internal/certs"
	"github.com/1337-llama/quic_research/internal/labserver"
	"github.com/1337-llama/quic_research/lab/internal/quicserver"
)

// Server is a running lab server on loopback.
type Server struct {
	Addr    string
	Pool    *x509.CertPool
	CertPEM []byte
	Handler *labserver.Handler

	mu      sync.Mutex
	remotes []string
	protos  []string
	agents  []string
}

// Start runs a lab server on 127.0.0.1 with a certificate for "localhost"
// and "127.0.0.1". It is stopped when the test ends.
func Start(t testing.TB) *Server {
	t.Helper()
	gen, err := certs.SelfSigned([]string{"localhost", "127.0.0.1"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := certs.PoolFromPEM(gen.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := quicserver.Listen(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Addr: pc.LocalAddr().String(), Pool: pool, CertPEM: gen.CertPEM, Handler: labserver.New(nil, nil)}
	srv := quicserver.New(s, gen.TLS)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(pc)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = pc.Close()
		<-done
	})
	return s
}

// ServeHTTP records request metadata, then delegates to the lab handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.remotes = append(s.remotes, r.RemoteAddr)
	s.protos = append(s.protos, r.Proto)
	s.agents = append(s.agents, r.UserAgent())
	s.mu.Unlock()
	s.Handler.ServeHTTP(w, r)
}

// Remotes returns the client address of every request, in order.
func (s *Server) Remotes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.remotes...)
}

// Protos returns the protocol of every request, in order.
func (s *Server) Protos() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.protos...)
}

// UserAgents returns the User-Agent of every request, in order.
func (s *Server) UserAgents() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.agents...)
}
