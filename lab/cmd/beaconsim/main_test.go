package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/certs"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/groundtruth"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/labserver"
	"github.com/1337-llama/QUIC-Research-and-Defense/lab/internal/labtest"
)

func TestRunEndToEnd(t *testing.T) {
	srv := labtest.Start(t)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, srv.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	truth := filepath.Join(dir, "truth.jsonl")
	keys := filepath.Join(dir, "keys.log")

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	code := run(ctx, []string{
		"-target", srv.Addr, "-server-name", "localhost", "-ca", ca,
		"-profile", "quicagent-like", "-interval", "20ms", "-jitter", "0", "-max-beacons", "3",
		"-truth", truth, "-keylog", keys, "-run-id", "e2e", "-log-format", "json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr.String())
	}

	f, err := os.Open(truth)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	recs, err := groundtruth.Read(f)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := groundtruth.Sessions(recs)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 3 || sessions[0].RunID != "e2e" || sessions[0].Label != "malicious" {
		t.Fatalf("sessions = %+v", sessions)
	}
	if info, err := os.Stat(keys); err != nil || info.Size() == 0 {
		t.Errorf("key log not written: %v", err)
	}
	if !strings.Contains(stderr.String(), `"msg":"run finished"`) {
		t.Errorf("missing completion log:\n%s", stderr.String())
	}
	if srv.Handler.Runs()["e2e"] != 3 {
		t.Errorf("server runs = %v", srv.Handler.Runs())
	}
}

func TestRunListProfilesAndUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-list-profiles"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "merlin-like") {
		t.Fatalf("list-profiles exit %d: %s", code, stdout.String())
	}
	if code := run(context.Background(), []string{"-h"}, &stdout, &stderr); code != 0 {
		t.Errorf("-h exit %d", code)
	}
	if code := run(context.Background(), []string{"-target", "x"}, &stdout, &stderr); code != 2 {
		t.Errorf("bad args exit %d", code)
	}
}

func TestRunFailsWithoutCA(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"-target", "127.0.0.1:1", "-ca", filepath.Join(t.TempDir(), "missing.pem"), "-ca-wait", "50ms",
		"-profile", "merlin-like",
	}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "reading -ca") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

func TestRunRefusesPublicTarget(t *testing.T) {
	srv := labtest.Start(t)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, srv.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"-target", "8.8.8.8:443", "-ca", ca, "-profile", "merlin-like", "-truth", filepath.Join(t.TempDir(), "t.jsonl"),
	}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "not a lab address") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

// TestRunFallsBackToTCP points the simulator at a server that only speaks
// HTTP/2 over TCP, as a network that blocks UDP/443 would leave it. Every
// session must complete over TCP and say so in ground truth.
func TestRunFallsBackToTCP(t *testing.T) {
	gen, err := certs.SelfSigned([]string{"localhost"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	handler := labserver.New(nil, nil)
	srv := labserver.NewTLSServer(handler, gen.TLS)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, gen.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	truth := filepath.Join(dir, "truth.jsonl")
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	code := run(ctx, []string{
		"-target", ln.Addr().String(), "-server-name", "localhost", "-ca", ca,
		"-profile", "quicagent-like", "-interval", "20ms", "-jitter", "0", "-max-beacons", "2",
		"-fallback", "-quic-timeout", "300ms", "-truth", truth, "-run-id", "fallback",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr.String())
	}
	f, err := os.Open(truth)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	recs, err := groundtruth.Read(f)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := groundtruth.Sessions(recs)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions = %+v", sessions)
	}
	for _, s := range sessions {
		if s.Transport != "tcp" || s.Remote.String() != ln.Addr().String() {
			t.Errorf("session = %+v, want a TCP session to %s", s, ln.Addr())
		}
	}
	if !strings.Contains(stderr.String(), "falling back") {
		t.Errorf("fallback not logged:\n%s", stderr.String())
	}
	if handler.Runs()["fallback"] != 2 {
		t.Errorf("server runs = %v", handler.Runs())
	}
}
