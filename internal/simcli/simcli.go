// Package simcli parses command-line options for the lab binaries.
//
// It lives in the dependency-free core module so that every flag, default
// and validation rule is unit-tested without a QUIC stack.
package simcli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/1337-llama/quic_research/internal/profile"
	"github.com/1337-llama/quic_research/internal/safety"
)

// FileReader reads a file. os.ReadFile satisfies it.
type FileReader func(name string) ([]byte, error)

// ClientOptions configures beaconsim.
type ClientOptions struct {
	Target       string
	ServerName   string
	CAFile       string
	CAWait       time.Duration
	KeyLogFile   string
	TruthFile    string
	RunID        string
	Seed         uint64
	Duration     time.Duration
	MaxBeacons   uint64
	AllowPublic  bool
	ListProfiles bool
	LogFormat    string
	LogLevel     string

	// Profile is the resolved, validated profile after overrides.
	Profile profile.Profile
}

// ParseClient parses beaconsim's arguments. It returns flag.ErrHelp if help
// was requested; usage has then already been written to stderr.
func ParseClient(args []string, stderr io.Writer, now func() time.Time, readFile FileReader) (ClientOptions, error) {
	var o ClientOptions
	var profileName, profileFile string
	var interval time.Duration
	var jitter float64

	fs := flag.NewFlagSet("beaconsim", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.Target, "target", "", "lab server `host:port` (required)")
	fs.StringVar(&o.ServerName, "server-name", "", "TLS server name / SNI (default: the target host)")
	fs.StringVar(&o.CAFile, "ca", "", "PEM `file` with the lab server's certificate (required)")
	fs.DurationVar(&o.CAWait, "ca-wait", 30*time.Second, "how long to wait for the -ca file to appear")
	fs.StringVar(&o.KeyLogFile, "keylog", "", "write TLS secrets to this `file` (NSS key log format) for Wireshark")
	fs.StringVar(&o.TruthFile, "truth", "", "write ground truth JSON Lines to this `file` (default: stdout)")
	fs.StringVar(&profileName, "profile", "", "built-in profile `name` (see -list-profiles)")
	fs.StringVar(&profileFile, "profile-file", "", "load a custom profile from this JSON `file`")
	fs.DurationVar(&interval, "interval", 0, "override the profile's interval")
	fs.Float64Var(&jitter, "jitter", -1, "override the profile's jitter fraction, 0 <= j < 1 (negative keeps the profile's value)")
	fs.StringVar(&o.RunID, "run-id", "", "identifier for this run (default: <profile>-<unix time>)")
	fs.Uint64Var(&o.Seed, "seed", 0, "random seed for timing and sizes (default: derived from the clock)")
	fs.DurationVar(&o.Duration, "duration", 0, "stop after this long (0 = until interrupted)")
	fs.Uint64Var(&o.MaxBeacons, "max-beacons", 0, "stop after this many beacons (0 = no limit)")
	fs.BoolVar(&o.AllowPublic, "allow-public-targets", false, "allow non-lab destinations (only for infrastructure you own)")
	fs.BoolVar(&o.ListProfiles, "list-profiles", false, "print the built-in profiles and exit")
	fs.StringVar(&o.LogFormat, "log-format", "text", "log format: text or json")
	fs.StringVar(&o.LogLevel, "log-level", "info", "log level: debug, info, warn or error")

	if err := fs.Parse(args); err != nil {
		return ClientOptions{}, err
	}
	if fs.NArg() > 0 {
		return ClientOptions{}, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if o.ListProfiles {
		return o, nil
	}

	var errs []error
	if o.Target == "" {
		errs = append(errs, errors.New("-target is required"))
	}
	if o.CAFile == "" {
		errs = append(errs, errors.New("-ca is required"))
	}
	if o.Duration < 0 {
		errs = append(errs, errors.New("-duration must not be negative"))
	}
	if o.CAWait < 0 {
		errs = append(errs, errors.New("-ca-wait must not be negative"))
	}
	if err := checkLogFlags(o.LogFormat, o.LogLevel); err != nil {
		errs = append(errs, err)
	}

	p, err := resolveProfile(profileName, profileFile, readFile)
	if err != nil {
		errs = append(errs, err)
	}
	o.Profile = p
	if len(errs) > 0 {
		return ClientOptions{}, errors.Join(errs...)
	}

	if interval != 0 {
		o.Profile.Schedule.Interval = profile.Duration(interval)
	}
	if jitter >= 0 {
		o.Profile.Schedule.Jitter = jitter
	}
	if err := o.Profile.Validate(); err != nil {
		return ClientOptions{}, fmt.Errorf("after overrides: %w", err)
	}

	t := now()
	if o.RunID == "" {
		o.RunID = fmt.Sprintf("%s-%d", o.Profile.Name, t.Unix())
	}
	if o.Seed == 0 {
		o.Seed = uint64(t.UnixNano()) //nolint:gosec // G115: wall-clock nanoseconds are positive; any value is a valid seed
	}
	return o, nil
}

func resolveProfile(name, file string, readFile FileReader) (profile.Profile, error) {
	switch {
	case name != "" && file != "":
		return profile.Profile{}, errors.New("use -profile or -profile-file, not both")
	case name == "" && file == "":
		return profile.Profile{}, errors.New("one of -profile or -profile-file is required")
	case name != "":
		return profile.Lookup(name)
	default:
		data, err := readFile(file)
		if err != nil {
			return profile.Profile{}, fmt.Errorf("reading -profile-file: %w", err)
		}
		return profile.Load(bytes.NewReader(data))
	}
}

// Policy returns the destination policy the options select.
func (o ClientOptions) Policy() safety.Policy {
	return safety.Policy{AllowPublic: o.AllowPublic}
}

// WriteProfiles prints the built-in profiles as a table.
func WriteProfiles(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tLABEL\tINTERVAL\tCONNECTIONS\tDESCRIPTION")
	for _, p := range profile.Builtin() {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.Name, p.Label, p.Schedule.Interval, p.Connection.Mode, p.Description)
	}
	return tw.Flush()
}

// ServerOptions configures beaconsrv.
type ServerOptions struct {
	Listen       string
	Hosts        []string
	CertOut      string
	CertValidity time.Duration
	LogFormat    string
	LogLevel     string
}

// ParseServer parses beaconsrv's arguments.
func ParseServer(args []string, stderr io.Writer) (ServerOptions, error) {
	var o ServerOptions
	var hosts string
	fs := flag.NewFlagSet("beaconsrv", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.Listen, "listen", ":443", "UDP `address` to listen on")
	fs.StringVar(&hosts, "hosts", "localhost,127.0.0.1", "comma-separated DNS names and IPs for the certificate")
	fs.StringVar(&o.CertOut, "cert-out", "", "write the generated certificate (PEM, no key) to this `file` (required)")
	fs.DurationVar(&o.CertValidity, "cert-validity", 24*time.Hour, "certificate lifetime")
	fs.StringVar(&o.LogFormat, "log-format", "text", "log format: text or json")
	fs.StringVar(&o.LogLevel, "log-level", "info", "log level: debug, info, warn or error")
	if err := fs.Parse(args); err != nil {
		return ServerOptions{}, err
	}
	if fs.NArg() > 0 {
		return ServerOptions{}, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	for _, h := range strings.Split(hosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			o.Hosts = append(o.Hosts, h)
		}
	}
	var errs []error
	if len(o.Hosts) == 0 {
		errs = append(errs, errors.New("-hosts must name at least one host"))
	}
	if o.CertOut == "" {
		errs = append(errs, errors.New("-cert-out is required"))
	}
	if o.CertValidity <= 0 {
		errs = append(errs, errors.New("-cert-validity must be positive"))
	}
	if o.Listen == "" {
		errs = append(errs, errors.New("-listen must not be empty"))
	}
	if err := checkLogFlags(o.LogFormat, o.LogLevel); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return ServerOptions{}, errors.Join(errs...)
	}
	return o, nil
}

func checkLogFlags(format, level string) error {
	_, err := NewLogger(io.Discard, format, level)
	return err
}

// NewLogger builds a slog.Logger writing to w.
func NewLogger(w io.Writer, format, level string) (*slog.Logger, error) {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("invalid log level %q", level)
	}
	opts := &slog.HandlerOptions{Level: lv}
	switch format {
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("invalid log format %q (want text or json)", format)
	}
}

// WaitForFile reads path, retrying every poll until it exists and is
// non-empty or timeout elapses. Lab containers use it to wait for the server
// to publish its certificate.
func WaitForFile(ctx context.Context, path string, timeout, poll time.Duration, readFile FileReader) ([]byte, error) {
	if poll <= 0 {
		return nil, errors.New("poll interval must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		data, err := readFile(path)
		if err == nil && len(data) > 0 {
			return data, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for %s: %w", path, ctx.Err())
		case <-t.C:
		}
	}
}

// OpenOutput opens path for writing, or returns stdout if path is empty or
// "-". The returned close function is always safe to call.
func OpenOutput(path string, stdout io.Writer) (io.Writer, func() error, error) {
	if path == "" || path == "-" {
		return stdout, func() error { return nil }, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // G304: the operator chooses the output path
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}
