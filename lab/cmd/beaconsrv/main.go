// Command beaconsrv is the detection lab's HTTP/3 server. It generates a
// fresh self-signed certificate at startup, publishes the certificate (never
// the key) for clients to trust, and acknowledges simulator beacons.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
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
	if err := writeFileAtomic(opts.CertOut, gen.CertPEM); err != nil {
		log.Error("publishing certificate", "path", opts.CertOut, "error", err)
		return 1
	}

	pc, err := quicserver.Listen(ctx, opts.Listen)
	if err != nil {
		log.Error("listening", "addr", opts.Listen, "error", err)
		return 1
	}
	handler := labserver.New(log, nil)
	srv := quicserver.New(handler, gen.TLS)

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(pc) }()
	log.Info("lab server listening", "addr", pc.LocalAddr().String(), "hosts", opts.Hosts, "cert", opts.CertOut)
	if ready != nil {
		ready <- pc.LocalAddr().String()
	}

	select {
	case <-ctx.Done():
		_ = srv.Close()
		_ = pc.Close()
		<-errc
		st := handler.Stats()
		log.Info("lab server stopped", "beacons", st.Beacons, "pages", st.Pages, "rejected", st.Rejected)
		return 0
	case err := <-errc:
		_ = pc.Close()
		log.Error("server failed", "error", err)
		return 1
	}
}

// writeFileAtomic writes data to a temporary file and renames it into
// place, so a client polling for the file never reads a partial certificate.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".cert-*.pem")
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
