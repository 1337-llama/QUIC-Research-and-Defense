// Package quicserver serves the lab server's handler over HTTP/3.
package quicserver

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// IdleTimeout is the server's QUIC idle timeout. It is generous so that
// each client profile's own idle timeout is what takes effect.
const IdleTimeout = 2 * time.Minute

// New returns an HTTP/3 server for handler using cert.
func New(handler http.Handler, cert tls.Certificate) *http3.Server {
	return &http3.Server{
		Handler: handler,
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}),
		QUICConfig: &quic.Config{MaxIdleTimeout: IdleTimeout},
	}
}

// Listen opens the UDP socket for addr.
func Listen(ctx context.Context, addr string) (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, "udp", addr)
}
