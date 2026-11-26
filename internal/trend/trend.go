// Package trend keeps the history of nightly lab results and renders it as a
// small dashboard: a Markdown page and an SVG chart of precision and recall
// per detector over time.
//
// The history is JSON Lines, one Entry per lab run, so it is easy to append
// to from CI, diff in review, and load into any other tool.
package trend

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/score"
)

// MaxLineBytes bounds one history line.
const MaxLineBytes = 1 << 20

// Metrics is one detector's result in one run.
type Metrics struct {
	Alerts    int     `json:"alerts"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

// Entry is one lab run.
type Entry struct {
	Time      time.Time          `json:"time"`
	Commit    string             `json:"commit"`
	RunURL    string             `json:"run_url,omitempty"`
	Passed    bool               `json:"passed"`
	Sessions  int                `json:"sessions"`
	Malicious int                `json:"malicious"`
	Benign    int                `json:"benign"`
	Detectors map[string]Metrics `json:"detectors"`
}

// Meta describes the run a report came from.
type Meta struct {
	Time   time.Time
	Commit string
	RunURL string
	Passed bool
}

// FromReport builds an entry from a scoring report.
func FromReport(r score.Report, m Meta) Entry {
	e := Entry{
		Time: m.Time.UTC(), Commit: m.Commit, RunURL: m.RunURL, Passed: m.Passed,
		Sessions: r.Sessions, Malicious: r.Malicious, Benign: r.Benign,
		Detectors: make(map[string]Metrics, len(r.Results)),
	}
	for _, res := range r.Results {
		e.Detectors[res.Detector] = Metrics{Alerts: res.Alerts, Precision: res.Precision, Recall: res.Recall, F1: res.F1}
	}
	return e
}

// Validate checks an entry.
func (e Entry) Validate() error {
	var errs []error
	if e.Time.IsZero() {
		errs = append(errs, errors.New("missing time"))
	}
	if e.Commit == "" {
		errs = append(errs, errors.New("missing commit"))
	}
	for name, m := range e.Detectors {
		for _, v := range []float64{m.Precision, m.Recall, m.F1} {
			if v < 0 || v > 1 {
				errs = append(errs, fmt.Errorf("detector %q: metric %v outside [0, 1]", name, v))
				break
			}
		}
	}
	return errors.Join(errs...)
}

// Read parses a history, oldest first. Blank lines are skipped.
func Read(r io.Reader) ([]Entry, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), MaxLineBytes)
	var out []Entry
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Entry
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("history line %d: %w", n, err)
		}
		if err := e.Validate(); err != nil {
			return nil, fmt.Errorf("history line %d: %w", n, err)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out, nil
}

// Append writes e as one history line.
func Append(w io.Writer, e Entry) error {
	if err := e.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

// Detectors returns the detectors to chart: those in the latest entry,
// with the combined score first and the rest sorted by name.
func Detectors(entries []Entry) []string {
	if len(entries) == 0 {
		return nil
	}
	latest := entries[len(entries)-1].Detectors
	out := make([]string, 0, len(latest))
	for name := range latest {
		if name != score.AnyDetector {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	if _, ok := latest[score.AnyDetector]; ok {
		out = append([]string{score.AnyDetector}, out...)
	}
	return out
}

// Last returns at most the n most recent entries.
func Last(entries []Entry, n int) []Entry {
	if n <= 0 || len(entries) <= n {
		return entries
	}
	return entries[len(entries)-n:]
}
