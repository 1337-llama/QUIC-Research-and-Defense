package groundtruth

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"net/netip"

	"github.com/1337-llama/quic_research/internal/profile"
)

var t0 = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func session(run string, id uint64, start time.Time) Record {
	return Record{
		Kind: KindSession, RunID: run, Profile: "merlin-like", Label: profile.LabelMalicious, SessionID: id,
		Local: netip.MustParseAddrPort("172.28.0.30:50000"), Remote: netip.MustParseAddrPort("172.28.0.10:443"),
		Start: start, End: start.Add(time.Minute), Beacons: 3,
	}
}

func TestWriterReadRoundTrip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := NewWriter(&buf)
	beacon := session("r", 1, t0)
	beacon.Kind, beacon.End, beacon.Beacons, beacon.Seq, beacon.BodyBytes = KindBeacon, time.Time{}, 0, 5, 300
	want := []Record{beacon, session("r", 1, t0)}
	for _, r := range want {
		if err := w.Record(r); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Count(buf.String(), "\n") != 2 {
		t.Fatalf("want 2 lines, got %q", buf.String())
	}
	if strings.Contains(strings.SplitN(buf.String(), "\n", 2)[0], `"end"`) {
		t.Errorf("beacon record should omit end: %s", buf.String())
	}
	got, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d records", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("record %d:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}
}

func TestWriterRejectsInvalid(t *testing.T) {
	t.Parallel()
	w := NewWriter(&bytes.Buffer{})
	bad := session("", 1, t0)
	if err := w.Record(bad); err == nil {
		t.Fatal("invalid record written")
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWriterPropagatesWriteErrors(t *testing.T) {
	t.Parallel()
	if err := NewWriter(errWriter{}).Record(session("r", 1, t0)); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("err = %v", err)
	}
}

func TestWriterConcurrentLinesStayIntact(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := NewWriter(&buf)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.Record(session("r", uint64(i), t0)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	recs, err := Read(&buf)
	if err != nil {
		t.Fatalf("interleaved output: %v", err)
	}
	if len(recs) != 50 {
		t.Fatalf("got %d records", len(recs))
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*Record){
		"unknown kind":     func(r *Record) { r.Kind = "x" },
		"no run":           func(r *Record) { r.RunID = "" },
		"bad label":        func(r *Record) { r.Label = "meh" },
		"no start":         func(r *Record) { r.Start = time.Time{} },
		"no remote":        func(r *Record) { r.Remote = netip.AddrPort{} },
		"no end":           func(r *Record) { r.End = time.Time{} },
		"end before start": func(r *Record) { r.End = r.Start.Add(-time.Second) },
	}
	for name, mut := range tests {
		r := session("r", 1, t0)
		mut(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
	if err := session("r", 1, t0).Validate(); err != nil {
		t.Errorf("valid record rejected: %v", err)
	}
}

func TestReadErrorsNameTheLine(t *testing.T) {
	t.Parallel()
	in := "\n" + `{"kind":"session"}` + "\n"
	_, err := Read(strings.NewReader(in))
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("err = %v", err)
	}
	_, err = Read(strings.NewReader("{oops\n"))
	if err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("err = %v", err)
	}
	_, err = Read(strings.NewReader(strings.Repeat("x", MaxLineBytes+10)))
	if err == nil {
		t.Fatal("oversized line accepted")
	}
}

func TestSessions(t *testing.T) {
	t.Parallel()
	b := session("r", 9, t0)
	b.Kind, b.End = KindBeacon, time.Time{}
	recs := []Record{session("r", 2, t0.Add(time.Hour)), b, session("r", 1, t0), session("s", 1, t0.Add(time.Minute))}
	got, err := Sessions(recs)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].SessionID != 1 || got[1].RunID != "s" || got[2].SessionID != 2 {
		t.Fatalf("Sessions = %+v", got)
	}
	if _, err := Sessions(append(recs, session("r", 1, t0))); err == nil {
		t.Fatal("duplicate session accepted")
	}
}

func TestDiscard(t *testing.T) {
	t.Parallel()
	if err := Discard.Record(Record{}); err != nil {
		t.Fatal(err)
	}
}
