package trend

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/score"
)

var t0 = time.Date(2026, 11, 20, 6, 17, 0, 0, time.UTC)

func entry(day int, recall float64, extra ...string) Entry {
	e := Entry{
		Time: t0.AddDate(0, 0, day), Commit: "0123456789abcdef0123456789abcdef01234567", Passed: recall >= 0.95,
		RunURL: "https://github.com/o/r/actions/runs/1", Sessions: 77, Malicious: 25, Benign: 52,
		Detectors: map[string]Metrics{
			score.AnyDetector:        {Alerts: 70, Precision: 1, Recall: recall, F1: recall},
			"unapproved-destination": {Alerts: 36, Precision: 1, Recall: 1, F1: 1},
			"long-connection":        {Alerts: 1, Precision: 1, Recall: 0.04, F1: 0.077},
		},
	}
	for _, d := range extra {
		e.Detectors[d] = Metrics{Precision: 0.5, Recall: 0.5, F1: 0.5}
	}
	return e
}

func TestFromReport(t *testing.T) {
	t.Parallel()
	rep := score.Report{Sessions: 3, Malicious: 1, Benign: 2, Results: []score.Result{
		{Detector: score.AnyDetector, Alerts: 2, Precision: 1, Recall: 1, F1: 1},
		{Detector: "long-connection", Alerts: 1, Precision: 1, Recall: 0.5, F1: 0.667},
	}}
	when := time.Date(2026, 11, 25, 1, 0, 0, 0, time.FixedZone("x", 3600))
	e := FromReport(rep, Meta{Time: when, Commit: "abc", RunURL: "u", Passed: true})
	if !e.Time.Equal(when) || e.Time.Location() != time.UTC || e.Commit != "abc" || !e.Passed || e.Sessions != 3 {
		t.Errorf("entry = %+v", e)
	}
	if m := e.Detectors["long-connection"]; m.Recall != 0.5 || m.Alerts != 1 {
		t.Errorf("metrics = %+v", m)
	}
}

func TestHistoryRoundTrip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	// Written out of order; Read returns them oldest first.
	for _, e := range []Entry{entry(2, 1), entry(0, 0.9), entry(1, 1)} {
		if err := Append(&buf, e); err != nil {
			t.Fatal(err)
		}
	}
	buf.WriteString("\n")
	got, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || !got[0].Time.Equal(t0) || got[0].Detectors[score.AnyDetector].Recall != 0.9 || !got[2].Time.Equal(t0.AddDate(0, 0, 2)) {
		t.Fatalf("history = %+v", got)
	}
}

func TestReadErrors(t *testing.T) {
	t.Parallel()
	for name, in := range map[string]string{
		"not json":      "{",
		"unknown field": `{"time":"2026-11-20T00:00:00Z","commit":"a","detectors":{},"bogus":1}`,
		"no commit":     `{"time":"2026-11-20T00:00:00Z","detectors":{}}`,
		"no time":       `{"commit":"a","detectors":{}}`,
		"bad metric":    `{"time":"2026-11-20T00:00:00Z","commit":"a","detectors":{"x":{"recall":1.5}}}`,
	} {
		if _, err := Read(strings.NewReader(in)); err == nil || !strings.Contains(err.Error(), "line 1") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := Read(iotest.ErrReader(iotest.ErrTimeout)); !errors.Is(err, iotest.ErrTimeout) {
		t.Errorf("read error = %v", err)
	}
	if err := Append(io.Discard, Entry{}); err == nil {
		t.Error("Append accepted an invalid entry")
	}
}

func TestDetectorsAndLast(t *testing.T) {
	t.Parallel()
	if Detectors(nil) != nil {
		t.Error("Detectors(nil) should be nil")
	}
	es := []Entry{entry(0, 1, "old-detector"), entry(1, 1)}
	got := strings.Join(Detectors(es), ",")
	if got != "(any),long-connection,unapproved-destination" {
		t.Errorf("Detectors = %s", got)
	}
	noAny := entry(2, 1)
	delete(noAny.Detectors, score.AnyDetector)
	if got := Detectors([]Entry{noAny}); got[0] != "long-connection" {
		t.Errorf("without (any): %v", got)
	}
	if len(Last(es, 1)) != 1 || len(Last(es, 5)) != 2 || len(Last(es, 0)) != 2 {
		t.Error("Last")
	}
}

// wellFormed fails unless data parses as XML.
func wellFormed(t *testing.T, data []byte) {
	t.Helper()
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		_, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatalf("SVG is not well-formed XML: %v\n%s", err, data)
		}
	}
}

func TestRenderSVG(t *testing.T) {
	t.Parallel()
	es := []Entry{entry(0, 0.9), entry(1, 1), entry(2, 1)}
	// A detector missing from the middle run breaks its line instead of
	// interpolating across the gap.
	es[0].Detectors[`suricata:<QUIC> & "JA4"`] = Metrics{Precision: 1, Recall: 0.2}
	es[2].Detectors[`suricata:<QUIC> & "JA4"`] = Metrics{Precision: 1, Recall: 0.3}
	dets := Detectors(es)
	svg := RenderSVG(es, dets)
	wellFormed(t, svg)
	s := string(svg)
	for _, want := range []string{
		`role="img"`, "<title id=\"t\">", "Precision and recall per detector, last 3 runs",
		"(any)", "long-connection", "suricata:&lt;QUIC&gt; &amp; &#34;JA4&#34;",
		"recall 0.04", "precision 1.00", "2026-11-20", "2026-11-22", "prefers-color-scheme: dark",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("SVG missing %q", want)
		}
	}
	if n := strings.Count(s, `class="panel-title"`); n != len(dets) {
		t.Errorf("%d panels, want %d", n, len(dets))
	}
	// (any), long-connection and unapproved-destination each draw two
	// three-point lines; the gapped detector has no segment longer than one
	// point, so it draws none.
	if n := strings.Count(s, "<polyline"); n != 6 {
		t.Errorf("%d polylines, want 6", n)
	}
	if n := strings.Count(s, `<circle`); n != 2*len(dets) {
		t.Errorf("%d end dots, want %d", n, 2*len(dets))
	}
}

func TestRenderSVGEdgeCases(t *testing.T) {
	t.Parallel()
	empty := RenderSVG(nil, nil)
	wellFormed(t, empty)
	if !strings.Contains(string(empty), "No lab runs recorded yet") {
		t.Error("empty chart has no message")
	}
	one := RenderSVG([]Entry{entry(0, 1)}, Detectors([]Entry{entry(0, 1)}))
	wellFormed(t, one)
	if strings.Contains(string(one), "<polyline") {
		t.Error("a single run should draw dots, not lines")
	}
}

func TestRenderMarkdown(t *testing.T) {
	t.Parallel()
	es := []Entry{entry(0, 1), entry(1, 0.9, "new|detector")}
	es[1].Passed = false
	es[1].Commit = "not-a-sha"
	var buf bytes.Buffer
	if err := RenderMarkdown(&buf, es, MarkdownOptions{RepoURL: "https://github.com/o/r/", ChartPath: "trend.svg", RecentRuns: 1}); err != nil {
		t.Fatal(err)
	}
	md := buf.String()
	for _, want := range []string{
		"gates **failed**", "| `(any)` | 1.000 | 0.900 | 0.900 | -0.100 |", "| `long-connection` | 1.000 | 0.040 | 0.077 | 0 |",
		"`new\\|detector`", "| new |", "![Precision and recall per detector over the last 2 runs](trend.svg)",
		"`not-a-s`", "[log](https://github.com/o/r/actions/runs/1)",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
	// RecentRuns: 1 lists only the newest run.
	if strings.Count(md, "| 2026-11-2") != 1 {
		t.Errorf("recent runs table:\n%s", md)
	}

	buf.Reset()
	if err := RenderMarkdown(&buf, es[:1], MarkdownOptions{RepoURL: "https://github.com/o/r"}); err != nil {
		t.Fatal(err)
	}
	md = buf.String()
	if !strings.Contains(md, "[`0123456`](https://github.com/o/r/commit/0123456789abcdef0123456789abcdef01234567)") ||
		!strings.Contains(md, "| – |") || strings.Contains(md, "## Over time") {
		t.Errorf("single-run page:\n%s", md)
	}

	buf.Reset()
	if err := RenderMarkdown(&buf, nil, MarkdownOptions{}); err != nil || !strings.Contains(buf.String(), "No lab runs recorded yet.") {
		t.Errorf("empty page: %v\n%s", err, buf.String())
	}
}

// TestWriteExample renders a sample dashboard for visual review when
// TREND_EXAMPLE_DIR is set; it is skipped otherwise.
func TestWriteExample(t *testing.T) {
	dir := os.Getenv("TREND_EXAMPLE_DIR")
	if dir == "" {
		t.Skip("set TREND_EXAMPLE_DIR to write an example dashboard")
	}
	var es []Entry
	for d := range 30 {
		r := 1.0
		if d%9 == 4 {
			r = 0.92
		}
		e := entry(d, r)
		e.Detectors["periodic-connections"] = Metrics{Precision: 1, Recall: 0.25 + 0.01*float64(d%5)}
		e.Detectors["intra-connection-cadence"] = Metrics{Precision: 1, Recall: 0.04}
		es = append(es, e)
	}
	if err := os.WriteFile(filepath.Join(dir, "trend.svg"), RenderSVG(es, Detectors(es)), 0o600); err != nil {
		t.Fatal(err)
	}
}
