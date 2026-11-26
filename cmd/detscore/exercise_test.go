package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/grade"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGradeCommand(t *testing.T) {
	t.Parallel()
	answers := writeTemp(t, "answers.txt", "172.28.0.30 # one long connection\n172.28.0.40\n")

	code, out, errOut := runCLI(t, "grade", "-truth", td("truth.jsonl"), "-answers", answers)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"score: 50/100", "found 1 of 2", "172.28.0.31", "quicagent-like", "FN", "FP"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	code, out, _ = runCLI(t, "grade", "-truth", td("truth.jsonl"), "-answers", answers, "-reveal=false")
	if code != exitOK || strings.Contains(out, "quicagent-like") || !strings.Contains(out, "score: 50/100") {
		t.Errorf("hidden debrief: exit %d\n%s", code, out)
	}

	code, out, _ = runCLI(t, "grade", "-truth", td("truth.jsonl"), "-answers", answers, "-format", "json")
	var res grade.Result
	if code != exitOK || json.Unmarshal([]byte(out), &res) != nil || res.TP != 1 || res.FP != 1 || res.FN != 1 {
		t.Errorf("json: exit %d, %+v\n%s", code, res, out)
	}
}

func TestGradeCommandErrors(t *testing.T) {
	t.Parallel()
	good := writeTemp(t, "a.txt", "172.28.0.30\n")
	bad := writeTemp(t, "b.txt", "merlin\n")
	tests := []struct {
		args []string
		code int
	}{
		{[]string{"grade", "-answers", good}, exitUsage},
		{[]string{"grade", "-truth", td("truth.jsonl")}, exitUsage},
		{[]string{"grade", "-truth", td("truth.jsonl"), "-answers", good, "-format", "xml"}, exitUsage},
		{[]string{"grade", "-truth", td("truth.jsonl"), "-answers", good, "-format", "json", "-reveal=false"}, exitUsage},
		{[]string{"grade", "-truth", td("truth.jsonl"), "-answers", bad}, exitError},
		{[]string{"grade", "-truth", td("missing.jsonl"), "-answers", good}, exitError},
		{[]string{"grade", "-truth", writeTemp(t, "empty.jsonl", ""), "-answers", good}, exitError},
	}
	for _, tc := range tests {
		if code, _, errOut := runCLI(t, tc.args...); code != tc.code {
			t.Errorf("%v: exit %d, want %d: %s", tc.args, code, tc.code, errOut)
		}
	}
}

func TestTrendCommand(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	history := filepath.Join(dir, "history.jsonl")
	out := filepath.Join(dir, "site")

	// Score the fixture to get a real report, then append it twice.
	report := filepath.Join(dir, "report.json")
	if code, _, errOut := runCLI(t, "score", "-truth", td("truth.jsonl"), "-alerts", td("alerts.golden.jsonl"),
		"-format", "json", "-out", report); code != exitOK {
		t.Fatalf("score: %s", errOut)
	}
	for i, when := range []string{"2026-11-24T06:17:00Z", "2026-11-25T06:17:00Z"} {
		code, _, errOut := runCLI(t, "trend", "-history", history, "-report", report, "-commit", "0123456789abcdef",
			"-time", when, "-passed", "-run-url", "https://example.test/run/1", "-repo-url", "https://github.com/o/r", "-out-dir", out)
		if code != exitOK {
			t.Fatalf("trend %d: exit %d: %s", i, code, errOut)
		}
	}
	data, err := os.ReadFile(history)
	if err != nil || strings.Count(string(data), "\n") != 2 {
		t.Fatalf("history: %v\n%s", err, data)
	}
	readme, err := os.ReadFile(filepath.Join(out, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# Detection lab results", "gates passed", "](trend.svg)", "[`0123456`](https://github.com/o/r/commit/0123456789abcdef)", "| `long-connection` |"} {
		if !strings.Contains(string(readme), want) {
			t.Errorf("README missing %q:\n%s", want, readme)
		}
	}
	svg, err := os.ReadFile(filepath.Join(out, "trend.svg"))
	if err != nil || !strings.Contains(string(svg), "last 2 runs") {
		t.Errorf("trend.svg: %v", err)
	}

	// Rendering alone, from a history that doesn't exist yet, still works.
	empty := filepath.Join(dir, "empty")
	if code, _, errOut := runCLI(t, "trend", "-history", filepath.Join(dir, "none.jsonl"), "-out-dir", empty); code != exitOK {
		t.Fatalf("empty: %s", errOut)
	}
	if b, _ := os.ReadFile(filepath.Join(empty, "README.md")); !strings.Contains(string(b), "No lab runs recorded yet.") {
		t.Errorf("empty README:\n%s", b)
	}
}

func TestTrendCommandErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	h := filepath.Join(dir, "h.jsonl")
	notReport := writeTemp(t, "r.json", `{"sessions":1}`)
	badHistory := writeTemp(t, "bad.jsonl", "{\n")
	tests := []struct {
		args []string
		code int
	}{
		{[]string{"trend", "-out-dir", dir}, exitUsage},
		{[]string{"trend", "-history", h}, exitUsage},
		{[]string{"trend", "-history", h, "-out-dir", dir, "-report", notReport}, exitUsage},
		{[]string{"trend", "-history", h, "-out-dir", dir, "-points", "0"}, exitUsage},
		{[]string{"trend", "-history", h, "-out-dir", dir, "-time", "yesterday"}, exitUsage},
		{[]string{"trend", "-history", h, "-out-dir", dir, "-report", notReport, "-commit", "abc"}, exitError},
		{[]string{"trend", "-history", h, "-out-dir", dir, "-report", filepath.Join(dir, "missing.json"), "-commit", "abc"}, exitError},
		{[]string{"trend", "-history", badHistory, "-out-dir", dir}, exitError},
		{[]string{"trend", "-history", h, "-out-dir", badHistory}, exitError},
	}
	for _, tc := range tests {
		if code, _, errOut := runCLI(t, tc.args...); code != tc.code {
			t.Errorf("%v: exit %d, want %d: %s", tc.args, code, tc.code, errOut)
		}
	}
}

func TestVersionCommand(t *testing.T) {
	t.Parallel()
	for _, arg := range []string{"version", "-version", "--version"} {
		code, out, _ := runCLI(t, arg)
		if code != exitOK || !strings.HasPrefix(out, "detscore ") {
			t.Errorf("%s: exit %d, %q", arg, code, out)
		}
	}
}
