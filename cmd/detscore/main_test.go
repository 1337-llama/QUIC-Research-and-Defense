package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func td(name string) string { return filepath.Join("testdata", name) }

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := td(name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden file (run with -update to create): %v", err)
	}
	if got != string(want) {
		t.Errorf("output differs from %s (run go test -update to accept):\n--- got\n%s\n--- want\n%s", path, got, want)
	}
}

var detectArgs = []string{
	"detect", "-conn", td("conn.log"), "-quic", td("quic.log"),
	"-long-connection", "5m", "-approved", "172.28.0.20/32",
}

func TestDetectGolden(t *testing.T) {
	code, out, errOut := runCLI(t, detectArgs...)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	golden(t, "alerts.golden.jsonl", out)

	// The fixture has known answers; spell them out so a bad golden file
	// cannot hide a regression.
	counts := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		for _, det := range []string{"long-connection", "unapproved-destination", "periodic-connections", "missing-sni", "nonstandard-port"} {
			if strings.Contains(line, `"detector":"`+det+`"`) {
				counts[det]++
			}
		}
	}
	want := map[string]int{"long-connection": 1, "unapproved-destination": 7, "periodic-connections": 6, "missing-sni": 1}
	for det, n := range want {
		if counts[det] != n {
			t.Errorf("%s alerts = %d, want %d", det, counts[det], n)
		}
	}
	if counts["nonstandard-port"] != 0 {
		t.Errorf("unexpected nonstandard-port alerts")
	}
}

func TestScoreGolden(t *testing.T) {
	alerts := filepath.Join(t.TempDir(), "alerts.jsonl")
	if code, _, errOut := runCLI(t, append(detectArgs, "-out", alerts)...); code != exitOK {
		t.Fatalf("detect exit %d: %s", code, errOut)
	}
	base := []string{"score", "-truth", td("truth.jsonl"), "-alerts", alerts, "-eve", td("eve.json"), "-notice", td("notice.log")}

	code, out, errOut := runCLI(t, base...)
	if code != exitOK {
		t.Fatalf("score exit %d: %s", code, errOut)
	}
	golden(t, "score.golden.txt", out)

	code, out, errOut = runCLI(t, append(base, "-format", "json")...)
	if code != exitOK {
		t.Fatalf("score json exit %d: %s", code, errOut)
	}
	golden(t, "score.golden.json", out)
	for _, want := range []string{`"sessions": 19`, `"malicious": 7`, `"benign": 12`} {
		if !strings.Contains(out, want) {
			t.Errorf("json report missing %s", want)
		}
	}
}

func TestScoreGates(t *testing.T) {
	alerts := filepath.Join(t.TempDir(), "alerts.jsonl")
	if code, _, errOut := runCLI(t, append(detectArgs, "-out", alerts)...); code != exitOK {
		t.Fatalf("detect exit %d: %s", code, errOut)
	}
	base := []string{"score", "-truth", td("truth.jsonl"), "-alerts", alerts, "-out", filepath.Join(t.TempDir(), "r.txt")}

	pass := append(append([]string{}, base...),
		"-require", "unapproved-destination:recall>=1",
		"-require", "unapproved-destination:precision>=1",
		"-require", "(any):recall>=1")
	if code, _, errOut := runCLI(t, pass...); code != exitOK {
		t.Fatalf("passing gates exit %d: %s", code, errOut)
	}

	fail := append(append([]string{}, base...),
		"-require", "long-connection:recall>=0.5",
		"-require", "(any):precision>=1",
		"-require", "never-fired:recall>=0.1")
	code, _, errOut := runCLI(t, fail...)
	if code != exitGateFail {
		t.Fatalf("failing gates exit %d, want %d: %s", code, exitGateFail, errOut)
	}
	for _, want := range []string{"3 requirement(s) not met", "long-connection:recall>=0.5: got 0.143", "(any):precision>=1: got 0.875", "never-fired"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr missing %q:\n%s", want, errOut)
		}
	}
}

func TestOutputFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "alerts.jsonl")
	code, stdout, errOut := runCLI(t, append(detectArgs, "-out", out)...)
	if code != exitOK || stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %s", code, stdout, errOut)
	}
	data, err := os.ReadFile(out)
	if err != nil || len(data) == 0 {
		t.Fatalf("output file: %v, %d bytes", err, len(data))
	}
}

func TestUsageAndErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
		msg  string
	}{
		{"no args", nil, exitUsage, "Usage:"},
		{"help", []string{"help"}, exitOK, ""},
		{"unknown command", []string{"frobnicate"}, exitUsage, `unknown command "frobnicate"`},
		{"detect help", []string{"detect", "-h"}, exitOK, "-long-connection"},
		{"detect no conn", []string{"detect"}, exitUsage, "-conn is required"},
		{"detect bad flag", []string{"detect", "-nope"}, exitUsage, "not defined"},
		{"detect extra arg", []string{"detect", "-conn", td("conn.log"), "extra"}, exitUsage, "unexpected arguments"},
		{"detect bad port", []string{"detect", "-conn", td("conn.log"), "-ports", "443,x"}, exitUsage, `invalid port "x"`},
		{"detect zero port", []string{"detect", "-conn", td("conn.log"), "-ports", "0"}, exitUsage, "invalid port"},
		{"detect bad cidr", []string{"detect", "-conn", td("conn.log"), "-approved", "10.0.0.0/99"}, exitUsage, "invalid network"},
		{"detect bad config", []string{"detect", "-conn", td("conn.log"), "-periodic-min", "2"}, exitUsage, "periodic minimum"},
		{"detect missing file", []string{"detect", "-conn", td("missing.log")}, exitError, "no such file"},
		{"detect bad quic file", []string{"detect", "-conn", td("conn.log"), "-quic", td("truth.jsonl")}, exitError, "quic"},
		{"detect bad out dir", []string{"detect", "-conn", td("conn.log"), "-out", td("no/such/dir/x")}, exitError, "no such file"},
		{"score no truth", []string{"score"}, exitUsage, "-truth file is required"},
		{"score bad format", []string{"score", "-truth", td("truth.jsonl"), "-format", "xml"}, exitUsage, "invalid -format"},
		{"score bad require", []string{"score", "-truth", td("truth.jsonl"), "-require", "x"}, exitUsage, "requirement"},
		{"score bad tolerance", []string{"score", "-truth", td("truth.jsonl"), "-tolerance", "-1s"}, exitError, "tolerance"},
		{"score bad truth", []string{"score", "-truth", td("conn.log")}, exitError, "groundtruth"},
		{"score missing alerts", []string{"score", "-truth", td("truth.jsonl"), "-alerts", td("missing")}, exitError, "no such file"},
		{"score bad eve", []string{"score", "-truth", td("truth.jsonl"), "-eve", td("notice.log")}, exitError, "eve"},
		{"score bad notice", []string{"score", "-truth", td("truth.jsonl"), "-notice", td("eve.json")}, exitError, "notice"},
		{"score duplicate truth", []string{"score", "-truth", td("truth.jsonl"), "-truth", td("truth.jsonl")}, exitError, "duplicate session"},
		{"score bad out", []string{"score", "-truth", td("truth.jsonl"), "-out", td("no/such/dir/x")}, exitError, "no such file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := runCLI(t, tc.args...)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, tc.code, out, errOut)
			}
			if tc.msg != "" && !strings.Contains(out+errOut, tc.msg) {
				t.Errorf("output missing %q\nstdout: %s\nstderr: %s", tc.msg, out, errOut)
			}
		})
	}
}

func TestParseHelpers(t *testing.T) {
	ports, err := parsePorts(" 443, 8443 ,")
	if err != nil || len(ports) != 2 || ports[1] != 8443 {
		t.Errorf("parsePorts = %v, %v", ports, err)
	}
	if ports, err := parsePorts(""); err != nil || len(ports) != 0 {
		t.Errorf("empty ports = %v, %v", ports, err)
	}
	nets, err := parsePrefixes("10.1.2.3/8, 172.28.0.20, fd00::/8")
	if err != nil || len(nets) != 3 || nets[0].String() != "10.0.0.0/8" || nets[1].String() != "172.28.0.20/32" {
		t.Errorf("parsePrefixes = %v, %v", nets, err)
	}
	var l listFlag
	_ = l.Set("a")
	_ = l.Set("b")
	if l.String() != "a,b" {
		t.Errorf("listFlag = %q", l.String())
	}
}
