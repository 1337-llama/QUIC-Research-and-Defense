package simcli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/profile"
)

var t0 = time.Unix(1_800_000_000, 123)

func now() time.Time { return t0 }

func files(m map[string]string) FileReader {
	return func(name string) ([]byte, error) {
		if s, ok := m[name]; ok {
			return []byte(s), nil
		}
		return nil, os.ErrNotExist
	}
}

func parseClient(t *testing.T, args ...string) (ClientOptions, error) {
	t.Helper()
	return ParseClient(args, io.Discard, now, files(nil))
}

func TestParseClientDefaults(t *testing.T) {
	t.Parallel()
	o, err := parseClient(t, "-target", "c2:443", "-ca", "ca.pem", "-profile", "merlin-like")
	if err != nil {
		t.Fatal(err)
	}
	if o.Profile.Name != "merlin-like" || o.RunID != "merlin-like-1800000000" || o.Seed == 0 {
		t.Errorf("defaults = %+v", o)
	}
	if o.AllowPublic || o.Duration != 0 || o.LogFormat != "text" || o.LogLevel != "info" || o.CAWait != 30*time.Second {
		t.Errorf("defaults = %+v", o)
	}
	if o.Policy().AllowPublic {
		t.Error("default policy must not allow public targets")
	}
	if o.Fallback || o.QUICTimeout != 10*time.Second {
		t.Errorf("fallback defaults = %v %v", o.Fallback, o.QUICTimeout)
	}
}

func TestParseClientFallbackAndRotation(t *testing.T) {
	t.Parallel()
	o, err := parseClient(t, "-target", "c2-tcp:443", "-ca", "ca.pem", "-profile", "rotating-session",
		"-fallback", "-quic-timeout", "3s", "-rotate-after", "2m")
	if err != nil {
		t.Fatal(err)
	}
	if !o.Fallback || o.QUICTimeout != 3*time.Second || o.Profile.Connection.RotateAfter.Std() != 2*time.Minute {
		t.Errorf("o = %+v", o)
	}
	for name, args := range map[string][]string{
		"rotate on persistent": {"-profile", "merlin-like", "-rotate-after", "2m"},
		"zero quic timeout":    {"-profile", "merlin-like", "-quic-timeout", "0s"},
	} {
		if _, err := parseClient(t, append([]string{"-target", "c2:443", "-ca", "ca.pem"}, args...)...); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestParseClientOverrides(t *testing.T) {
	t.Parallel()
	o, err := parseClient(t, "-target", "c2:443", "-ca", "ca.pem", "-profile", "quicagent-like",
		"-interval", "5s", "-jitter", "0", "-run-id", "x", "-seed", "9", "-duration", "1m",
		"-max-beacons", "3", "-allow-public-targets", "-log-format", "json", "-log-level", "debug")
	if err != nil {
		t.Fatal(err)
	}
	if o.Profile.Schedule.Interval.Std() != 5*time.Second || o.Profile.Schedule.Jitter != 0 {
		t.Errorf("schedule = %+v", o.Profile.Schedule)
	}
	if o.RunID != "x" || o.Seed != 9 || o.Duration != time.Minute || o.MaxBeacons != 3 || !o.AllowPublic || !o.Policy().AllowPublic {
		t.Errorf("options = %+v", o)
	}
}

func TestParseClientProfileFile(t *testing.T) {
	t.Parallel()
	p, _ := profile.Lookup("browser-like")
	p.Name = "custom"
	var buf bytes.Buffer
	if err := writeJSON(&buf, p); err != nil {
		t.Fatal(err)
	}
	read := files(map[string]string{"p.json": buf.String(), "bad.json": `{"name":"bad"}`})
	o, err := ParseClient([]string{"-target", "c2:443", "-ca", "a", "-profile-file", "p.json"}, io.Discard, now, read)
	if err != nil || o.Profile.Name != "custom" {
		t.Fatalf("o = %+v, err = %v", o, err)
	}
	if _, err := ParseClient([]string{"-target", "c2:443", "-ca", "a", "-profile-file", "bad.json"}, io.Discard, now, read); err == nil {
		t.Error("invalid profile file accepted")
	}
	if _, err := ParseClient([]string{"-target", "c2:443", "-ca", "a", "-profile-file", "missing.json"}, io.Discard, now, read); err == nil {
		t.Error("missing profile file accepted")
	}
}

func TestParseClientErrors(t *testing.T) {
	t.Parallel()
	tests := map[string][]string{
		"missing everything":  {},
		"both profiles":       {"-target", "a:1", "-ca", "c", "-profile", "merlin-like", "-profile-file", "x"},
		"unknown profile":     {"-target", "a:1", "-ca", "c", "-profile", "nope"},
		"missing target":      {"-ca", "c", "-profile", "merlin-like"},
		"missing ca":          {"-target", "a:1", "-profile", "merlin-like"},
		"negative duration":   {"-target", "a:1", "-ca", "c", "-profile", "merlin-like", "-duration", "-1s"},
		"bad jitter":          {"-target", "a:1", "-ca", "c", "-profile", "merlin-like", "-jitter", "1.5"},
		"bad interval":        {"-target", "a:1", "-ca", "c", "-profile", "merlin-like", "-interval", "1ns"},
		"jitter on exp":       {"-target", "a:1", "-ca", "c", "-profile", "browser-like", "-jitter", "0.2"},
		"bad log format":      {"-target", "a:1", "-ca", "c", "-profile", "merlin-like", "-log-format", "xml"},
		"bad log level":       {"-target", "a:1", "-ca", "c", "-profile", "merlin-like", "-log-level", "loud"},
		"unknown flag":        {"-bogus"},
		"positional argument": {"-target", "a:1", "-ca", "c", "-profile", "merlin-like", "extra"},
		"negative ca-wait":    {"-target", "a:1", "-ca", "c", "-profile", "merlin-like", "-ca-wait", "-1s"},
		"bad run id":          {"-target", "a:1", "-ca", "c", "-profile", "merlin-like", "-run-id", "bad id"},
	}
	for name, args := range tests {
		if _, err := parseClient(t, args...); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestParseClientHelpAndList(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	_, err := ParseClient([]string{"-h"}, &stderr, now, files(nil))
	if !errors.Is(err, flag.ErrHelp) || !strings.Contains(stderr.String(), "-allow-public-targets") {
		t.Fatalf("err = %v, usage = %q", err, stderr.String())
	}
	o, err := parseClient(t, "-list-profiles")
	if err != nil || !o.ListProfiles {
		t.Fatalf("o = %+v, err = %v", o, err)
	}
	var out bytes.Buffer
	if err := WriteProfiles(&out); err != nil {
		t.Fatal(err)
	}
	for _, p := range profile.Builtin() {
		if !strings.Contains(out.String(), p.Name) {
			t.Errorf("profile list missing %s:\n%s", p.Name, out.String())
		}
	}
}

func TestParseServer(t *testing.T) {
	t.Parallel()
	o, err := ParseServer([]string{"-cert-out", "c.pem", "-hosts", " c2 , 172.28.0.10,,"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if o.Listen != ":443" || len(o.Hosts) != 2 || o.Hosts[0] != "c2" || o.Hosts[1] != "172.28.0.10" || o.CertValidity != 24*time.Hour {
		t.Errorf("o = %+v", o)
	}
	if o.ListenTCP != "" || o.SPKIOut != "" {
		t.Errorf("TCP listener should be off by default: %+v", o)
	}
	tcpOnly, err := ParseServer([]string{"-cert-out", "c.pem", "-listen", "", "-listen-tcp", ":443", "-spki-out", "s"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if tcpOnly.Listen != "" || tcpOnly.ListenTCP != ":443" || tcpOnly.SPKIOut != "s" {
		t.Errorf("tcp-only = %+v", tcpOnly)
	}
	bad := map[string][]string{
		"no cert-out":   {},
		"no hosts":      {"-cert-out", "c", "-hosts", " , "},
		"zero validity": {"-cert-out", "c", "-cert-validity", "0s"},
		"no listeners":  {"-cert-out", "c", "-listen", ""},
		"bad log":       {"-cert-out", "c", "-log-format", "xml"},
		"positional":    {"-cert-out", "c", "x"},
		"unknown flag":  {"-nope"},
	}
	for name, args := range bad {
		if _, err := ParseServer(args, io.Discard); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestNewLogger(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l, err := NewLogger(&buf, "json", "warn")
	if err != nil {
		t.Fatal(err)
	}
	l.Info("hidden")
	l.Warn("shown", "k", "v")
	if strings.Contains(buf.String(), "hidden") || !strings.Contains(buf.String(), `"k":"v"`) {
		t.Errorf("log output = %q", buf.String())
	}
	if _, err := NewLogger(&buf, "text", "debug"); err != nil {
		t.Error(err)
	}
}

func TestOpenOutput(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	for _, p := range []string{"", "-"} {
		w, closeFn, err := OpenOutput(p, &stdout)
		if err != nil || w != &stdout || closeFn() != nil {
			t.Errorf("OpenOutput(%q) = %v, %v", p, w, err)
		}
	}
	path := filepath.Join(t.TempDir(), "out.jsonl")
	w, closeFn, err := OpenOutput(path, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "hello"); err != nil {
		t.Fatal(err)
	}
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() != 5 || info.Mode().Perm() != 0o600 {
		t.Errorf("file = %v, %v", info, err)
	}
	if _, _, err := OpenOutput(filepath.Join(t.TempDir(), "missing", "x"), &stdout); err == nil {
		t.Error("expected error for missing directory")
	}
}

func TestWaitForFile(t *testing.T) {
	t.Parallel()
	calls := 0
	read := func(string) ([]byte, error) {
		calls++
		switch calls {
		case 1:
			return nil, os.ErrNotExist
		case 2:
			return []byte{}, nil // created but not yet written
		default:
			return []byte("pem"), nil
		}
	}
	data, err := WaitForFile(context.Background(), "ca.pem", time.Second, time.Millisecond, read)
	if err != nil || string(data) != "pem" || calls != 3 {
		t.Fatalf("data = %q, err = %v, calls = %d", data, err, calls)
	}

	_, err = WaitForFile(context.Background(), "ca.pem", 20*time.Millisecond, time.Millisecond, files(nil))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("timeout err = %v", err)
	}
	perm := func(string) ([]byte, error) { return nil, os.ErrPermission }
	if _, err := WaitForFile(context.Background(), "x", time.Second, time.Millisecond, perm); !errors.Is(err, os.ErrPermission) {
		t.Errorf("permission err = %v", err)
	}
	if _, err := WaitForFile(context.Background(), "x", time.Second, 0, perm); err == nil {
		t.Error("zero poll accepted")
	}
}

func TestVersionFlag(t *testing.T) {
	t.Parallel()
	// -version needs none of the otherwise required flags.
	if o, err := parseClient(t, "-version"); err != nil || !o.ShowVersion {
		t.Errorf("client: %+v, %v", o, err)
	}
	if o, err := ParseServer([]string{"-version"}, io.Discard); err != nil || !o.ShowVersion {
		t.Errorf("server: %+v, %v", o, err)
	}
}
