// Command detscore runs reference QUIC detections over Zeek logs and scores
// any detections (its own, Zeek notices, Suricata alerts) against the
// beacon simulator's ground truth.
//
// Usage:
//
//	detscore detect -conn conn.log [-quic quic.log] [flags]
//	detscore score  -truth truth.jsonl [-alerts a.jsonl] [-eve eve.json] [-notice notice.log] [flags]
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/1337-llama/quic_research/internal/detect"
	"github.com/1337-llama/quic_research/internal/eve"
	"github.com/1337-llama/quic_research/internal/groundtruth"
	"github.com/1337-llama/quic_research/internal/score"
	"github.com/1337-llama/quic_research/internal/simcli"
	"github.com/1337-llama/quic_research/internal/zeeklog"
)

// Exit codes.
const (
	exitOK       = 0
	exitError    = 1
	exitUsage    = 2
	exitGateFail = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `detscore: score QUIC detections against beacon-simulator ground truth.

Usage:
  detscore detect -conn conn.log [-quic quic.log] [flags]
  detscore score  -truth truth.jsonl [-alerts alerts.jsonl] [-eve eve.json] [-notice notice.log] [flags]

Run "detscore <command> -h" for a command's flags.

Exit codes: 0 success, 1 error, 2 usage error, 3 a -require gate failed.
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	var err error
	switch args[0] {
	case "detect":
		err = runDetect(args[1:], stdout, stderr)
	case "score":
		err = runScore(args[1:], stdout, stderr)
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "detscore: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
	var ue usageError
	var ge gateError
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, flag.ErrHelp):
		return exitOK
	case errors.As(err, &ue):
		fmt.Fprintf(stderr, "detscore: %v\n", err)
		return exitUsage
	case errors.As(err, &ge):
		fmt.Fprintf(stderr, "detscore: %v\n", err)
		return exitGateFail
	default:
		fmt.Fprintf(stderr, "detscore: %v\n", err)
		return exitError
	}
}

type usageError struct{ error }

func (e usageError) Unwrap() error { return e.error }

type gateError struct{ error }

func (e gateError) Unwrap() error { return e.error }

// listFlag collects repeated string flags.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError{err}
	}
	if fs.NArg() > 0 {
		return usageError{fmt.Errorf("unexpected arguments: %v", fs.Args())}
	}
	return nil
}

func runDetect(args []string, stdout, stderr io.Writer) error {
	cfg := detect.DefaultConfig()
	var connPath, quicPath, outPath, ports, approved string
	fs := flag.NewFlagSet("detscore detect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&connPath, "conn", "", "Zeek conn.log (TSV or JSON) (required)")
	fs.StringVar(&quicPath, "quic", "", "Zeek quic.log (TSV or JSON)")
	fs.StringVar(&outPath, "out", "", "write alerts (JSON Lines) to this file (default: stdout)")
	fs.DurationVar(&cfg.LongConnection, "long-connection", cfg.LongConnection, "flag QUIC connections at least this long (0 disables)")
	fs.StringVar(&ports, "ports", "443", "comma-separated expected QUIC ports (empty disables)")
	fs.StringVar(&approved, "approved", "", "comma-separated approved destination CIDRs (empty disables)")
	fs.IntVar(&cfg.PeriodicMinConns, "periodic-min", cfg.PeriodicMinConns, "minimum connections to judge periodicity (0 disables)")
	fs.Float64Var(&cfg.PeriodicMaxCV, "periodic-max-cv", cfg.PeriodicMaxCV, "maximum coefficient of variation of connection gaps")
	fs.BoolVar(&cfg.MissingSNI, "missing-sni", cfg.MissingSNI, "flag QUIC handshakes without SNI")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if connPath == "" {
		return usageError{errors.New("-conn is required")}
	}
	var err error
	if cfg.StandardPorts, err = parsePorts(ports); err != nil {
		return usageError{err}
	}
	if cfg.ApprovedNets, err = parsePrefixes(approved); err != nil {
		return usageError{err}
	}
	if err := cfg.Validate(); err != nil {
		return usageError{err}
	}

	conns, err := readFile(connPath, zeeklog.ReadConns)
	if err != nil {
		return err
	}
	var quics []zeeklog.QUIC
	if quicPath != "" {
		if quics, err = readFile(quicPath, zeeklog.ReadQUIC); err != nil {
			return err
		}
	}
	alerts, err := detect.Run(cfg, conns, quics)
	if err != nil {
		return err
	}
	data, err := detect.MarshalAlerts(alerts)
	if err != nil {
		return err
	}
	return writeOutput(outPath, stdout, data)
}

func runScore(args []string, stdout, stderr io.Writer) error {
	var truth, alertFiles, eveFiles, noticeFiles, requires listFlag
	var outPath, format string
	opt := score.Options{Tolerance: score.DefaultTolerance}
	fs := flag.NewFlagSet("detscore score", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Var(&truth, "truth", "simulator ground truth JSON Lines (repeatable, required)")
	fs.Var(&alertFiles, "alerts", "alerts from 'detscore detect' (repeatable)")
	fs.Var(&eveFiles, "eve", "Suricata eve.json (repeatable)")
	fs.Var(&noticeFiles, "notice", "Zeek notice.log (repeatable)")
	fs.Var(&requires, "require", "fail (exit 3) unless detector:metric>=value holds, e.g. '(any):recall>=0.95' (repeatable)")
	fs.DurationVar(&opt.Tolerance, "tolerance", opt.Tolerance, "timestamp slack when matching alerts to sessions")
	fs.StringVar(&format, "format", "text", "output format: text or json")
	fs.StringVar(&outPath, "out", "", "write the report to this file (default: stdout)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if len(truth) == 0 {
		return usageError{errors.New("at least one -truth file is required")}
	}
	if format != "text" && format != "json" {
		return usageError{fmt.Errorf("invalid -format %q (want text or json)", format)}
	}
	reqs := make([]score.Requirement, 0, len(requires))
	for _, s := range requires {
		q, err := score.ParseRequirement(s)
		if err != nil {
			return usageError{err}
		}
		reqs = append(reqs, q)
	}

	sessions, err := loadSessions(truth)
	if err != nil {
		return err
	}
	alerts, err := loadAlerts(alertFiles, eveFiles, noticeFiles)
	if err != nil {
		return err
	}
	rep, err := score.Score(sessions, alerts, opt)
	if err != nil {
		return err
	}
	w, closeOut, err := simcli.OpenOutput(outPath, stdout)
	if err != nil {
		return err
	}
	if format == "json" {
		err = score.WriteJSON(w, rep)
	} else {
		err = score.WriteText(w, rep)
	}
	if cerr := closeOut(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if errs := score.Check(rep, reqs); len(errs) > 0 {
		return gateError{fmt.Errorf("%d requirement(s) not met:\n  %w", len(errs), joinLines(errs))}
	}
	return nil
}

func loadSessions(paths []string) ([]groundtruth.Record, error) {
	var records []groundtruth.Record
	for _, p := range paths {
		recs, err := readFile(p, groundtruth.Read)
		if err != nil {
			return nil, err
		}
		records = append(records, recs...)
	}
	return groundtruth.Sessions(records)
}

// loadAlerts reads and normalizes alerts from every supported source.
func loadAlerts(detectFiles, eveFiles, noticeFiles []string) ([]score.Alert, error) {
	var alerts []score.Alert
	for _, p := range detectFiles {
		as, err := readFile(p, detect.ReadAlerts)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, score.FromDetect(as)...)
	}
	for _, p := range eveFiles {
		as, err := readFile(p, eve.ReadAlerts)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, score.FromEVE(as)...)
	}
	for _, p := range noticeFiles {
		ns, err := readFile(p, zeeklog.ReadNotices)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, score.FromNotices(ns)...)
	}
	return alerts, nil
}

func joinLines(errs []error) error {
	parts := make([]string, len(errs))
	for i, e := range errs {
		parts[i] = e.Error()
	}
	return errors.New(strings.Join(parts, "\n  "))
}

func readFile[T any](path string, parse func(io.Reader) (T, error)) (T, error) {
	var zero T
	f, err := os.Open(path)
	if err != nil {
		return zero, err
	}
	defer func() { _ = f.Close() }() // read-only: a close error cannot lose data
	v, err := parse(f)
	if err != nil {
		return zero, fmt.Errorf("%s: %w", path, err)
	}
	return v, nil
}

func writeOutput(path string, stdout io.Writer, data []byte) error {
	w, closeOut, err := simcli.OpenOutput(path, stdout)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	if cerr := closeOut(); err == nil {
		err = cerr
	}
	return err
}

func parsePorts(s string) ([]uint16, error) {
	items := splitList(s)
	out := make([]uint16, 0, len(items))
	for _, p := range items {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		out = append(out, uint16(n))
	}
	return out, nil
}

func parsePrefixes(s string) ([]netip.Prefix, error) {
	items := splitList(s)
	out := make([]netip.Prefix, 0, len(items))
	for _, p := range items {
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			a, aerr := netip.ParseAddr(p)
			if aerr != nil {
				return nil, fmt.Errorf("invalid network %q", p)
			}
			pfx = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, pfx.Masked())
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
