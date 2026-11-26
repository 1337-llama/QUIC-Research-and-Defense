package main

import (
	"bytes"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/groundtruth"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/pcap"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/pcap/pcaptest"
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

// writeBeaconPcap writes a capture with one regularly beaconing QUIC
// connection and one irregular one.
func writeBeaconPcap(t *testing.T) string {
	t.Helper()
	w := pcaptest.New(pcaptest.Options{LinkType: pcap.LinkEthernet})
	t0 := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	c2 := netip.MustParseAddrPort("172.28.0.10:443")
	beacon := netip.MustParseAddrPort("172.28.0.30:40001")
	browse := netip.MustParseAddrPort("172.28.0.40:42001")
	irregular := []int{0, 3, 4, 31, 33, 70, 71, 72, 118, 160, 163, 220}
	for i := range 20 {
		at := t0.Add(time.Duration(i) * 15 * time.Second)
		w.UDP(at, beacon, c2, 1200)
		w.UDP(at.Add(3*time.Millisecond), c2, beacon, 1200)
	}
	for _, s := range irregular {
		at := t0.Add(time.Duration(s) * time.Second)
		w.UDP(at, browse, c2, 1200)
		w.UDP(at.Add(3*time.Millisecond), c2, browse, 900)
	}
	path := filepath.Join(t.TempDir(), "lab.pcap")
	if err := os.WriteFile(path, w.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCadenceCommand(t *testing.T) {
	path := writeBeaconPcap(t)
	code, out, errOut := runCLI(t, "cadence", "-pcap", path)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], `"detector":"intra-connection-cadence"`) ||
		!strings.Contains(lines[0], `"orig":"172.28.0.30:40001"`) || !strings.Contains(lines[0], "20 client bursts") {
		t.Fatalf("output = %s", out)
	}
	// The alerts feed straight into the scorer.
	alerts := filepath.Join(t.TempDir(), "cadence.jsonl")
	if code, _, errOut := runCLI(t, "cadence", "-pcap", path, "-out", alerts); code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if code, _, errOut := runCLI(t, "score", "-truth", td("truth.jsonl"), "-alerts", alerts,
		"-require", "intra-connection-cadence:precision>=1"); code != exitOK {
		t.Fatalf("score exit %d: %s", code, errOut)
	}
}

func TestLabelCommand(t *testing.T) {
	out := filepath.Join(t.TempDir(), "truth-bg.jsonl")
	code, _, errOut := runCLI(t, "label", "-conn", td("conn.log"), "-host", "172.28.0.40",
		"-label", "benign", "-profile", "chromium", "-run-id", "chromium", "-out", out)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	recs, err := groundtruth.Read(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 12 { // the 12 QUIC connections; the DNS connection is excluded
		t.Fatalf("got %d records", len(recs))
	}
	if recs[0].Profile != "chromium" || recs[0].Label != "benign" || recs[0].Remote.String() != "172.28.0.20:443" {
		t.Errorf("record = %+v", recs[0])
	}
	code, stdout, _ := runCLI(t, "label", "-conn", td("conn.log"), "-host", "172.28.0.40", "-service", "",
		"-label", "benign", "-profile", "p", "-run-id", "r")
	if code != exitOK || strings.Count(stdout, "\n") != 13 {
		t.Errorf("all-services label: exit %d, %d lines", code, strings.Count(stdout, "\n"))
	}
}

func TestJA4Command(t *testing.T) {
	code, out, errOut := runCLI(t, "ja4", "-eve", td("eve-ja4.json"), "-truth", td("truth.jsonl"))
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	golden(t, "ja4.golden.txt", out)
	for _, want := range []string{"merlin-like (malicious)", "quicagent-like (malicious)", "browser-like (benign)", "q13d0313h3", "172.28.0.50"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q:\n%s", want, out)
		}
	}
	code, out, _ = runCLI(t, "ja4", "-eve", td("eve-ja4.json"), "-format", "json")
	if code != exitOK || !strings.Contains(out, `"events": 3`) {
		t.Errorf("json summary: exit %d\n%s", code, out)
	}
	code, out, _ = runCLI(t, "ja4", "-eve", td("eve.json"))
	if code != exitOK || !strings.Contains(out, "no JA4 fingerprints") {
		t.Errorf("empty summary: exit %d\n%s", code, out)
	}
}

func TestNewCommandErrors(t *testing.T) {
	pcapPath := writeBeaconPcap(t)
	tests := []struct {
		name string
		args []string
		code int
		msg  string
	}{
		{"cadence no pcap", []string{"cadence"}, exitUsage, "-pcap is required"},
		{"cadence bad port", []string{"cadence", "-pcap", pcapPath, "-ports", "x"}, exitUsage, "invalid port"},
		{"cadence bad config", []string{"cadence", "-pcap", pcapPath, "-min-bursts", "1"}, exitUsage, "minimum bursts"},
		{"cadence not pcap", []string{"cadence", "-pcap", td("conn.log")}, exitError, "pcap"},
		{"cadence bad flag", []string{"cadence", "-nope"}, exitUsage, "not defined"},
		{"label no conn", []string{"label"}, exitUsage, "-conn is required"},
		{"label bad host", []string{"label", "-conn", td("conn.log"), "-host", "x"}, exitUsage, "invalid -host"},
		{"label bad spec", []string{"label", "-conn", td("conn.log"), "-host", "10.0.0.1", "-label", "meh"}, exitUsage, "label"},
		{"label missing file", []string{"label", "-conn", td("missing"), "-host", "10.0.0.1", "-label", "benign", "-profile", "p", "-run-id", "r"}, exitError, "no such file"},
		{"label bad out", []string{"label", "-conn", td("conn.log"), "-host", "10.0.0.1", "-label", "benign", "-profile", "p", "-run-id", "r", "-out", td("no/dir/x")}, exitError, "no such file"},
		{"ja4 no eve", []string{"ja4"}, exitUsage, "-eve file is required"},
		{"ja4 bad format", []string{"ja4", "-eve", td("eve-ja4.json"), "-format", "xml"}, exitUsage, "invalid -format"},
		{"ja4 bad eve", []string{"ja4", "-eve", td("notice.log")}, exitError, "eve"},
		{"ja4 bad truth", []string{"ja4", "-eve", td("eve-ja4.json"), "-truth", td("conn.log")}, exitError, "groundtruth"},
		{"ja4 bad out", []string{"ja4", "-eve", td("eve-ja4.json"), "-out", td("no/dir/x")}, exitError, "no such file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := runCLI(t, tc.args...)
			if code != tc.code || !strings.Contains(out+errOut, tc.msg) {
				t.Fatalf("exit %d (want %d), output missing %q\nstdout: %s\nstderr: %s", code, tc.code, tc.msg, out, errOut)
			}
		})
	}
}
