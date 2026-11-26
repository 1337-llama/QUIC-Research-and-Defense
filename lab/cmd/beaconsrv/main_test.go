package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/beacon"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/certs"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/profile"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/tlstransport"
	"github.com/1337-llama/QUIC-Research-and-Defense/lab/internal/quictransport"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestServeAndShutdown(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.pem")
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	var stderr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"-listen", "127.0.0.1:0", "-hosts", "localhost,127.0.0.1", "-cert-out", certPath}, &stderr, ready)
	}()

	var addr string
	select {
	case addr = <-ready:
	case code := <-done:
		t.Fatalf("server exited early with %d: %s", code, stderr.String())
	case <-time.After(10 * time.Second):
		t.Fatal("server did not start")
	}

	pem, err := os.ReadFile(certPath)
	if err != nil || !strings.Contains(string(pem), "BEGIN CERTIFICATE") || strings.Contains(string(pem), "PRIVATE KEY") {
		t.Fatalf("published certificate is wrong: %v\n%s", err, pem)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, ".tmp-*"))
	if len(matches) != 0 {
		t.Errorf("temporary files left behind: %v", matches)
	}

	pool, err := certs.PoolFromPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := profile.Lookup("merlin-like")
	p.Schedule.Interval = profile.Duration(20 * time.Millisecond)
	tr, err := quictransport.New(quictransport.Config{Target: addr, ServerName: "localhost", RootCAs: pool, QUIC: p.QUIC})
	if err != nil {
		t.Fatal(err)
	}
	st, err := beacon.Run(context.Background(), beacon.Config{Profile: p, RunID: "srv-test", Transport: tr, MaxBeacons: 2})
	if err != nil || st.Beacons != 2 {
		t.Fatalf("beacons against beaconsrv: %+v, %v", st, err)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not shut down")
	}
	if !strings.Contains(stderr.String(), "beacons=2") {
		t.Errorf("shutdown log should report beacon count:\n%s", stderr.String())
	}
}

func TestUsageErrors(t *testing.T) {
	var stderr syncBuffer
	if code := run(context.Background(), []string{"-h"}, &stderr, nil); code != 0 {
		t.Errorf("-h exit %d", code)
	}
	if code := run(context.Background(), nil, &stderr, nil); code != 2 {
		t.Errorf("missing -cert-out exit %d", code)
	}
	if code := run(context.Background(), []string{"-cert-out", filepath.Join(t.TempDir(), "no", "dir", "c.pem")}, &stderr, nil); code != 1 {
		t.Errorf("unwritable cert path exit %d", code)
	}
	if code := run(context.Background(), []string{"-cert-out", filepath.Join(t.TempDir(), "c.pem"), "-listen", "256.0.0.1:1"}, &stderr, nil); code != 1 {
		t.Errorf("bad listen address exit %d", code)
	}
}

func TestServeBothTransports(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.pem")
	spkiPath := filepath.Join(dir, "server.spki")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stderr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"-listen", "127.0.0.1:0", "-listen-tcp", "127.0.0.1:0", "-hosts", "localhost",
			"-cert-out", certPath, "-spki-out", spkiPath}, &stderr, nil)
	}()
	certPEM, err := waitForFile(certPath)
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	pool, err := certs.PoolFromPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := os.ReadFile(spkiPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := parseCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(spki)), certs.SPKIHash(leaf); got != want {
		t.Errorf("SPKI file = %q, want %q", got, want)
	}

	tcpAddr := tcpAddrFromLog(t, &stderr)
	tr, err := tlstransport.New(tlstransport.Config{Target: tcpAddr, ServerName: "localhost", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := profile.Lookup("merlin-like")
	p.Schedule.Interval = profile.Duration(20 * time.Millisecond)
	st, err := beacon.Run(context.Background(), beacon.Config{Profile: p, RunID: "srv-tcp", Transport: tr, MaxBeacons: 2})
	if err != nil || st.Beacons != 2 {
		t.Fatalf("beacons over TCP: %+v, %v", st, err)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

func TestTCPListenError(t *testing.T) {
	var stderr syncBuffer
	code := run(context.Background(), []string{"-listen", "127.0.0.1:0", "-listen-tcp", "256.0.0.1:1",
		"-cert-out", filepath.Join(t.TempDir(), "c.pem")}, &stderr, nil)
	if code != 1 || !strings.Contains(stderr.String(), "tcp 256.0.0.1:1") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

func waitForFile(path string) ([]byte, error) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			return data, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil, errors.New("certificate was not published")
}

func parseCert(data []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(b.Bytes)
}

var tcpAddrRE = regexp.MustCompile(`tcp/(127\.0\.0\.1:\d+)`)

// tcpAddrFromLog returns the TCP address from the server's startup log line.
func tcpAddrFromLog(t *testing.T, stderr *syncBuffer) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m := tcpAddrRE.FindStringSubmatch(stderr.String()); m != nil {
			return m[1]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no TCP listener in log:\n%s", stderr.String())
	return ""
}
