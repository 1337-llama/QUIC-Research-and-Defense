// Command beaconsrv is the detection lab's server: HTTP/3 over QUIC and,
// optionally, HTTP/2 over TLS/TCP for the fallback scenario. It generates a
// fresh self-signed certificate at startup, publishes the certificate (never
// the key) for clients to trust, and acknowledges simulator beacons.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/certs"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/labserver"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/simcli"
	"github.com/1337-llama/QUIC-Research-and-Defense/lab/internal/quicserver"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stderr, nil)
	stop()
	os.Exit(code)
}

// run starts the server and blocks until ctx is done. If ready is non-nil,
// the bound address is sent on it once the server is listening.
func run(ctx context.Context, args []string, stderr io.Writer, ready chan<- string) int {
	opts, err := simcli.ParseServer(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "beaconsrv: %v\n", err)
		return 2
	}
	log, err := simcli.NewLogger(stderr, opts.LogFormat, opts.LogLevel)
	if err != nil {
		fmt.Fprintf(stderr, "beaconsrv: %v\n", err)
		return 2
	}

	gen, err := certs.SelfSigned(opts.Hosts, time.Now(), opts.CertValidity)
	if err != nil {
		log.Error("generating certificate", "error", err)
		return 1
	}
	// Clients wait for the certificate, so the SPKI hash goes first: once the
	// certificate appears, everything a client might need is in place.
	if opts.SPKIOut != "" {
		if err := writeFileAtomic(opts.SPKIOut, []byte(certs.SPKIHash(gen.TLS.Leaf)+"\n")); err != nil {
			log.Error("publishing SPKI hash", "path", opts.SPKIOut, "error", err)
			return 1
		}
	}
	if err := writeFileAtomic(opts.CertOut, gen.CertPEM); err != nil {
		log.Error("publishing certificate", "path", opts.CertOut, "error", err)
		return 1
	}

	handler := labserver.New(log, nil)
	servers, err := listen(ctx, opts, handler, gen.TLS)
	if err != nil {
		log.Error("listening", "error", err)
		return 1
	}

	errc := make(chan error, len(servers))
	var addrs []string
	for _, s := range servers {
		go func() { errc <- s.serve() }()
		addrs = append(addrs, s.network+"/"+s.addr)
	}
	log.Info("lab server listening", "addrs", addrs, "hosts", opts.Hosts, "cert", opts.CertOut)
	if ready != nil {
		ready <- servers[0].addr
	}

	var failed error
	select {
	case <-ctx.Done():
	case failed = <-errc:
	}
	for _, s := range servers {
		_ = s.close()
	}
	for range len(servers) - btoi(failed != nil) {
		<-errc
	}
	if failed != nil {
		log.Error("server failed", "error", failed)
		return 1
	}
	st := handler.Stats()
	log.Info("lab server stopped", "beacons", st.Beacons, "pages", st.Pages, "rejected", st.Rejected)
	return 0
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// server is one listener: HTTP/3 on UDP or HTTP/2 on TLS/TCP.
type server struct {
	network string
	addr    string
	serve   func() error
	close   func() error
}

// listen binds every configured listener, UDP first, so ready reports the
// QUIC address when there is one. On error it closes what it opened.
func listen(ctx context.Context, opts simcli.ServerOptions, h http.Handler, cert tls.Certificate) ([]server, error) {
	var out []server
	closeAll := func() {
		for _, s := range out {
			_ = s.close()
		}
	}
	if opts.Listen != "" {
		pc, err := quicserver.Listen(ctx, opts.Listen)
		if err != nil {
			return nil, fmt.Errorf("udp %s: %w", opts.Listen, err)
		}
		srv := quicserver.New(h, cert)
		out = append(out, server{
			network: "udp", addr: pc.LocalAddr().String(),
			serve: func() error { return srv.Serve(pc) },
			close: func() error { return errors.Join(srv.Close(), ignoreClosed(pc.Close())) },
		})
	}
	if opts.ListenTCP != "" {
		var lc net.ListenConfig
		ln, err := lc.Listen(ctx, "tcp", opts.ListenTCP)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("tcp %s: %w", opts.ListenTCP, err)
		}
		srv := labserver.NewTLSServer(h, cert)
		out = append(out, server{
			network: "tcp", addr: ln.Addr().String(),
			serve: func() error {
				if err := srv.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
					return err
				}
				return nil
			},
			close: srv.Close,
		})
	}
	return out, nil
}

func ignoreClosed(err error) error {
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// writeFileAtomic writes data to a temporary file and renames it into
// place, so a client polling for the file never reads a partial certificate.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// The certificate is public: clients in other containers must read it.
	if err := os.Chmod(tmp, 0o644); err != nil { //nolint:gosec // G302: a certificate is public by design
		return err
	}
	return os.Rename(tmp, path)
}
