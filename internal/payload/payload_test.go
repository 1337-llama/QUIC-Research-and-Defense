package payload

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func rng() *rand.ChaCha8 { return rand.NewChaCha8([32]byte{1}) }

func TestNewBeaconHitsTargetSize(t *testing.T) {
	t.Parallel()
	_, unpadded, err := NewBeacon("run-1", 7, t0, 0, rng())
	if err != nil {
		t.Fatal(err)
	}
	for target := 0; target <= 5000; target += 37 {
		b, body, err := NewBeacon("run-1", 7, t0, target, rng())
		if err != nil {
			t.Fatalf("target %d: %v", target, err)
		}
		if target <= len(unpadded)+12 {
			if len(b.Pad) != 0 || !bytes.Equal(body, unpadded) {
				t.Fatalf("target %d: expected unpadded beacon, got %d bytes", target, len(body))
			}
			continue
		}
		if len(body) > target || len(body) < target-3 {
			t.Fatalf("target %d: body is %d bytes", target, len(body))
		}
	}
}

func TestBeaconRoundTrip(t *testing.T) {
	t.Parallel()
	want, body, err := NewBeacon("run-x", 42, t0.In(time.FixedZone("x", 3600)), 512, rng())
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeBeacon(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Run != want.Run || got.Seq != want.Seq || !got.Sent.Equal(t0) || !bytes.Equal(got.Pad, want.Pad) {
		t.Fatalf("round trip mismatch: %+v vs %+v", got, want)
	}
	if got.Sent.Location() != time.UTC {
		t.Errorf("Sent should be normalized to UTC")
	}
}

func TestPaddingIsRandom(t *testing.T) {
	t.Parallel()
	b, _, err := NewBeacon("r", 1, t0, 2048, rng())
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[byte]int)
	for _, c := range b.Pad {
		counts[c]++
	}
	if len(counts) < 200 {
		t.Errorf("padding uses only %d distinct byte values; expected high entropy", len(counts))
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestNewBeaconPropagatesRandomErrors(t *testing.T) {
	t.Parallel()
	if _, _, err := NewBeacon("r", 1, t0, 1000, failingReader{}); err == nil {
		t.Fatal("expected error from failing random source")
	}
	// No padding needed, so the reader is never consulted.
	if _, _, err := NewBeacon("r", 1, t0, 10, failingReader{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewBeaconRejectsBadInput(t *testing.T) {
	t.Parallel()
	for _, size := range []int{-1, MaxBodyBytes + 1, int(^uint(0) >> 1)} {
		if _, _, err := NewBeacon("r", 1, t0, size, rng()); err == nil {
			t.Errorf("target size %d accepted", size)
		}
	}
	if _, body, err := NewBeacon("r", 1, t0, MaxBodyBytes, rng()); err != nil || len(body) > MaxBodyBytes {
		t.Errorf("max target size: %d bytes, %v", len(body), err)
	}
	for _, run := range []string{"", "a b", "line\nbreak", "x\x1b[31m", strings.Repeat("a", MaxRunIDLen+1)} {
		if _, _, err := NewBeacon(run, 1, t0, 0, rng()); err == nil {
			t.Errorf("run id %q accepted", run)
		}
	}
}

func TestValidRunID(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"merlin", "browser-1", "merlin-like-1800000000", "a.b_c:d", strings.Repeat("z", MaxRunIDLen)} {
		if err := ValidRunID(ok); err != nil {
			t.Errorf("ValidRunID(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "has space", "new\nline", "tab\t", "slash/", "ünïcode", strings.Repeat("z", MaxRunIDLen+1)} {
		if err := ValidRunID(bad); err == nil {
			t.Errorf("ValidRunID(%q) accepted", bad)
		}
	}
}

func TestDecodeBeaconErrors(t *testing.T) {
	t.Parallel()
	good, _ := json.Marshal(Beacon{Sim: Marker, Run: "r", Seq: 1, Sent: t0})
	tests := map[string][]byte{
		"empty":         nil,
		"not json":      []byte("hello"),
		"wrong marker":  []byte(`{"sim":"other","run":"r","seq":1,"sent":"2026-11-23T12:00:00Z"}`),
		"no run":        []byte(`{"sim":"` + Marker + `","seq":1,"sent":"2026-11-23T12:00:00Z"}`),
		"bad run":       []byte(`{"sim":"` + Marker + `","run":"a\nb","seq":1,"sent":"2026-11-23T12:00:00Z"}`),
		"unknown field": []byte(`{"sim":"` + Marker + `","run":"r","seq":1,"sent":"2026-11-23T12:00:00Z","cmd":"x"}`),
		"trailing":      append(append([]byte{}, good...), []byte(` {}`)...),
		"too large":     bytes.Repeat([]byte(" "), MaxBodyBytes+1),
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeBeacon(in); err == nil {
				t.Fatalf("DecodeBeacon accepted %s", name)
			}
		})
	}
}

func TestAck(t *testing.T) {
	t.Parallel()
	b, _, _ := NewBeacon("run-9", 3, t0, 0, rng())
	ack := NewAck(b, t0.Add(time.Second))
	data, err := json.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAck(data, b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Seq != 3 || got.Run != "run-9" || !got.Received.Equal(t0.Add(time.Second)) {
		t.Fatalf("ack = %+v", got)
	}

	other := b
	other.Seq = 4
	if _, err := DecodeAck(data, other); err == nil || !strings.Contains(err.Error(), "seq 3") {
		t.Errorf("mismatched seq accepted: %v", err)
	}
	if _, err := DecodeAck([]byte(`{"sim":"x","run":"run-9","seq":3}`), b); err == nil {
		t.Error("ack with wrong marker accepted")
	}
	if _, err := DecodeAck([]byte(`{`), b); err == nil {
		t.Error("truncated ack accepted")
	}
}

func FuzzDecodeBeacon(f *testing.F) {
	_, body, _ := NewBeacon("seed", 1, t0, 300, rng())
	f.Add(body)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"sim":"` + Marker + `","run":"r"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := DecodeBeacon(data)
		if err != nil {
			return
		}
		if b.Sim != Marker || ValidRunID(b.Run) != nil {
			t.Fatalf("accepted invalid beacon %+v", b)
		}
		// An accepted beacon must re-encode to something that decodes again.
		re, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeBeacon(re); err != nil {
			t.Fatalf("re-decode: %v", err)
		}
	})
}
