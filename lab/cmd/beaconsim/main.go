// Command beaconsim generates labeled QUIC beacon traffic against a lab
// server for detection training. It sends benign, self-identifying payloads,
// has no capability beyond that, and refuses non-lab destinations by
// default.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/beacon"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/certs"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/groundtruth"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/simcli"
	"github.com/1337-llama/QUIC-Research-and-Defense/lab/internal/quictransport"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	opts, err := simcli.ParseClient(args, stderr, time.Now, os.ReadFile)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "beaconsim: %v\n", err)
		return 2
	}
	if opts.ListProfiles {
		if err := simcli.WriteProfiles(stdout); err != nil {
			fmt.Fprintf(stderr, "beaconsim: %v\n", err)
			return 1
		}
		return 0
	}
	log, err := simcli.NewLogger(stderr, opts.LogFormat, opts.LogLevel)
	if err != nil {
		fmt.Fprintf(stderr, "beaconsim: %v\n", err)
		return 2
	}
	if err := simulate(ctx, opts, stdout, log); err != nil {
		log.Error("run failed", "error", err)
		return 1
	}
	return 0
}

func simulate(ctx context.Context, opts simcli.ClientOptions, stdout io.Writer, log *slog.Logger) error {
	caPEM, err := simcli.WaitForFile(ctx, opts.CAFile, opts.CAWait, 250*time.Millisecond, os.ReadFile)
	if err != nil {
		return fmt.Errorf("reading -ca: %w", err)
	}
	pool, err := certs.PoolFromPEM(caPEM)
	if err != nil {
		return fmt.Errorf("-ca %s: %w", opts.CAFile, err)
	}

	truthW, closeTruth, err := simcli.OpenOutput(opts.TruthFile, stdout)
	if err != nil {
		return fmt.Errorf("opening -truth: %w", err)
	}
	defer func() { _ = closeTruth() }()

	var keyLog io.Writer
	if opts.KeyLogFile != "" {
		w, closeKeys, err := simcli.OpenOutput(opts.KeyLogFile, stdout)
		if err != nil {
			return fmt.Errorf("opening -keylog: %w", err)
		}
		defer func() { _ = closeKeys() }()
		keyLog = w
	}

	tr, err := quictransport.New(quictransport.Config{
		Target: opts.Target, ServerName: opts.ServerName, RootCAs: pool, KeyLog: keyLog,
		QUIC: opts.Profile.QUIC, Policy: opts.Policy(),
	})
	if err != nil {
		return err
	}

	log.Info("starting run", "run_id", opts.RunID, "profile", opts.Profile.Name, "label", opts.Profile.Label,
		"target", opts.Target, "seed", opts.Seed, "duration", opts.Duration, "max_beacons", opts.MaxBeacons)
	stats, err := beacon.Run(ctx, beacon.Config{
		Profile: opts.Profile, RunID: opts.RunID, Seed: opts.Seed, Transport: tr,
		Recorder: groundtruth.NewWriter(truthW), Logger: log,
		MaxBeacons: opts.MaxBeacons, Duration: opts.Duration,
	})
	log.Info("run finished", "run_id", opts.RunID, "sessions", stats.Sessions, "beacons", stats.Beacons, "failures", stats.Failures)
	if err != nil {
		return err
	}
	return closeTruth()
}
