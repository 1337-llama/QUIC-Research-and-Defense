package labserver

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/certs"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/payload"
)

var t0 = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func newHandler() *Handler { return New(nil, func() time.Time { return t0 }) }

func beaconBody(t *testing.T, run string, seq uint64, size int) (payload.Beacon, []byte) {
	t.Helper()
	b, body, err := payload.NewBeacon(run, seq, t0, size, rand.NewChaCha8([32]byte{}))
	if err != nil {
		t.Fatal(err)
	}
	return b, body
}

func TestBeaconIsAcknowledged(t *testing.T) {
	t.Parallel()
	h := newHandler()
	b, body := beaconBody(t, "run-1", 5, 400)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/update", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	ack, err := payload.DecodeAck(rec.Body.Bytes(), b)
	if err != nil {
		t.Fatalf("DecodeAck: %v", err)
	}
	if !ack.Received.Equal(t0) {
		t.Errorf("Received = %v", ack.Received)
	}
	if got := h.Stats(); got != (Stats{Beacons: 1}) {
		t.Errorf("Stats = %+v", got)
	}
	if got := h.Runs(); got["run-1"] != 5 {
		t.Errorf("Runs = %v", got)
	}
}

func TestAckCarriesNoInstructions(t *testing.T) {
	t.Parallel()
	// Guard against anyone adding a tasking field to the protocol: the ack
	// must contain exactly these keys.
	h := newHandler()
	_, body := beaconBody(t, "r", 1, 0)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	var m map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"sim": true, "run": true, "seq": true, "received": true}
	if len(m) != len(want) {
		t.Fatalf("ack keys = %v", m)
	}
	for k := range m {
		if !want[k] {
			t.Fatalf("unexpected ack key %q", k)
		}
	}
}

func TestGetAndHead(t *testing.T) {
	t.Parallel()
	h := newHandler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/anything", http.NoBody))
	if rec.Code != http.StatusOK || rec.Body.String() != IndexHTML {
		t.Fatalf("GET = %d %q", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("missing Cache-Control")
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/", http.NoBody))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("HEAD = %d %q", rec.Code, rec.Body)
	}
	if got := h.Stats(); got.Pages != 2 {
		t.Errorf("Pages = %d", got.Pages)
	}
}

func TestRejections(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		method string
		body   io.Reader
		want   int
	}{
		{"bad method", http.MethodPut, nil, http.StatusMethodNotAllowed},
		{"garbage", http.MethodPost, strings.NewReader("garbage"), http.StatusBadRequest},
		{"wrong marker", http.MethodPost, strings.NewReader(`{"sim":"x","run":"r","seq":1,"sent":"2026-01-01T00:00:00Z"}`), http.StatusBadRequest},
		{"too large", http.MethodPost, bytes.NewReader(make([]byte, payload.MaxBodyBytes+1)), http.StatusRequestEntityTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHandler()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, "/", tc.body))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if got := h.Stats(); got.Rejected != 1 || got.Beacons != 0 {
				t.Errorf("Stats = %+v", got)
			}
		})
	}
}

func TestRunsTracksHighestSeq(t *testing.T) {
	t.Parallel()
	h := newHandler()
	for _, seq := range []uint64{3, 1, 7, 2} {
		_, body := beaconBody(t, "r", seq, 0)
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	}
	runs := h.Runs()
	if runs["r"] != 7 {
		t.Fatalf("Runs = %v", runs)
	}
	runs["r"] = 0
	if h.Runs()["r"] != 7 {
		t.Fatal("Runs must return a copy")
	}
}

func TestConcurrentBeacons(t *testing.T) {
	t.Parallel()
	h := New(nil, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, body := beaconBody(t, "r", uint64(i+1), 200)
			resp, err := http.Post(srv.URL+"/", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("status %d", resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	if got := h.Stats().Beacons; got != 20 {
		t.Fatalf("Beacons = %d", got)
	}
	if h.Runs()["r"] != 20 {
		t.Fatalf("Runs = %v", h.Runs())
	}
}

func TestLogSafe(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"plain":                  "plain",
		"/a\nfake=entry":         "/afake=entry",
		"x\r\ny":                 "xy",
		"esc\x1b[31mred\x00":     "esc[31mred",
		strings.Repeat("a", 300): strings.Repeat("a", 256) + "...(truncated)",
	}
	for in, want := range tests {
		if got := logSafe(in); got != want {
			t.Errorf("logSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClientInputCannotForgeLogLines(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	h := New(slog.New(slog.NewTextHandler(&buf, nil)), nil)
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("garbage"))
	req.URL.Path = "/x\nlevel=ERROR msg=forged"
	req.RemoteAddr = "10.0.0.1:1\r\nlevel=ERROR"
	h.ServeHTTP(httptest.NewRecorder(), req)
	if n := strings.Count(buf.String(), "\n"); n != 1 {
		t.Fatalf("one request produced %d log lines:\n%s", n, buf.String())
	}
}

func TestNewTLSServer(t *testing.T) {
	t.Parallel()
	g, err := certs.SelfSigned([]string{"c2-tcp"}, t0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewTLSServer(newHandler(), g.TLS)
	if srv.ReadHeaderTimeout != ReadHeaderTimeout || srv.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("server limits not set: %+v", srv)
	}
	if got := srv.TLSConfig.NextProtos; len(got) != 2 || got[0] != "h2" || got[1] != "http/1.1" {
		t.Errorf("NextProtos = %v", got)
	}
	if len(srv.TLSConfig.Certificates) != 1 {
		t.Error("certificate not installed")
	}
}
