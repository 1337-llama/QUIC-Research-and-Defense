// Package labserver implements the lab server's HTTP handler. It is
// transport-agnostic: the lab module serves it over HTTP/3, and tests serve
// it over plain HTTP.
//
// The handler acknowledges simulator beacons and serves a static page. It
// never returns instructions of any kind.
package labserver

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/payload"
)

// IndexHTML is served for GET requests.
const IndexHTML = `<!doctype html>
<html><head><title>quic_research lab server</title></head>
<body><p>This is a quic_research detection-lab server. It only acknowledges simulator traffic.</p></body></html>
`

// Stats counts what the handler has seen.
type Stats struct {
	Beacons  uint64
	Pages    uint64
	Rejected uint64
}

// Handler is the lab server's http.Handler.
type Handler struct {
	log *slog.Logger
	now func() time.Time

	beacons  atomic.Uint64
	pages    atomic.Uint64
	rejected atomic.Uint64

	mu   sync.Mutex
	runs map[string]uint64 // highest sequence number seen per run
}

// New returns a Handler. A nil logger discards logs; a nil now uses time.Now.
func New(log *slog.Logger, now func() time.Time) *Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if now == nil {
		now = time.Now
	}
	return &Handler{log: log, now: now, runs: make(map[string]uint64)}
}

// Stats returns a snapshot of the counters.
func (h *Handler) Stats() Stats {
	return Stats{Beacons: h.beacons.Load(), Pages: h.pages.Load(), Rejected: h.rejected.Load()}
}

// Runs returns the highest sequence number seen for each run ID.
func (h *Handler) Runs() map[string]uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]uint64, len(h.runs))
	for k, v := range h.runs {
		out[k] = v
	}
	return out
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		h.pages.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, IndexHTML)
		}
	case http.MethodPost:
		h.handleBeacon(w, r)
	default:
		h.rejected.Add(1)
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleBeacon(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, payload.MaxBodyBytes))
	if err != nil {
		h.reject(w, r, http.StatusRequestEntityTooLarge, err)
		return
	}
	b, err := payload.DecodeBeacon(body)
	if err != nil {
		h.reject(w, r, http.StatusBadRequest, err)
		return
	}
	h.beacons.Add(1)
	h.mu.Lock()
	if b.Seq > h.runs[b.Run] {
		h.runs[b.Run] = b.Seq
	}
	h.mu.Unlock()
	// Every request-derived value goes through logSafe, numbers included, so
	// the rule is uniform and easy to audit.
	h.log.Info("beacon", "run_id", logSafe(b.Run), "seq", logSafe(strconv.FormatUint(b.Seq, 10)), "path", logSafe(r.URL.Path),
		"remote", logSafe(r.RemoteAddr), "bytes", len(body))

	ack, err := json.Marshal(payload.NewAck(b, h.now()))
	if err != nil { // cannot happen for this struct, but never ignore errors
		h.reject(w, r, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(ack)
}

func (h *Handler) reject(w http.ResponseWriter, r *http.Request, code int, err error) {
	h.rejected.Add(1)
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		code = http.StatusRequestEntityTooLarge
	}
	h.log.Warn("rejected request", "remote", logSafe(r.RemoteAddr), "path", logSafe(r.URL.Path),
		"status", code, "error", logSafe(err.Error()))
	http.Error(w, http.StatusText(code), code)
}

// maxLogValue bounds client-controlled values in log entries.
const maxLogValue = 256

// logSafe neutralizes client-controlled text before it is logged: line
// breaks (which could forge log entries in line-oriented logs) and other
// control characters are removed, and the value is truncated.
func logSafe(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if len(s) > maxLogValue {
		s = s[:maxLogValue] + "...(truncated)"
	}
	return s
}
