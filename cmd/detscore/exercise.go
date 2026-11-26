package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/grade"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/score"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/simcli"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/trend"
)

// runGrade scores an analyst's answers to a lab exercise.
func runGrade(args []string, stdout, stderr io.Writer) error {
	var truth listFlag
	var answersPath, format, outPath string
	var reveal bool
	fs := flag.NewFlagSet("detscore grade", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Var(&truth, "truth", "ground truth from the exercise's answer key (repeatable, required)")
	fs.StringVar(&answersPath, "answers", "", "the analyst's answers: one client IP per line, '#' starts a comment (required)")
	fs.BoolVar(&reveal, "reveal", true, "show the per-host debrief (labels and profiles); false prints only the score")
	fs.StringVar(&format, "format", "text", "output format: text or json")
	fs.StringVar(&outPath, "out", "", "write the result to this file (default: stdout)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if len(truth) == 0 {
		return usageError{errors.New("at least one -truth file is required")}
	}
	if answersPath == "" {
		return usageError{errors.New("-answers is required")}
	}
	if format != "text" && format != "json" {
		return usageError{fmt.Errorf("invalid -format %q (want text or json)", format)}
	}
	if format == "json" && !reveal {
		return usageError{errors.New("-format json always includes the debrief; use text with -reveal=false")}
	}
	sessions, err := loadSessions(truth)
	if err != nil {
		return err
	}
	answers, err := readFile(answersPath, grade.ParseAnswers)
	if err != nil {
		return err
	}
	res, err := grade.Grade(sessions, answers)
	if err != nil {
		return err
	}
	w, closeOut, err := simcli.OpenOutput(outPath, stdout)
	if err != nil {
		return err
	}
	if format == "json" {
		err = grade.WriteJSON(w, res)
	} else {
		err = grade.WriteText(w, res, reveal)
	}
	if cerr := closeOut(); err == nil {
		err = cerr
	}
	return err
}

// runTrend appends a lab report to the results history and renders the
// dashboard (README.md and trend.svg) from it.
func runTrend(args []string, _, stderr io.Writer) error {
	var historyPath, reportPath, outDir, commit, runURL, repoURL, when string
	var passed bool
	var points int
	fs := flag.NewFlagSet("detscore trend", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&historyPath, "history", "", "results history, JSON Lines; created if missing (required)")
	fs.StringVar(&reportPath, "report", "", "a 'detscore score -format json' report to append (optional)")
	fs.StringVar(&commit, "commit", "", "commit the report was produced from (required with -report)")
	fs.StringVar(&runURL, "run-url", "", "link to the CI run")
	fs.BoolVar(&passed, "passed", false, "whether the run's gates passed")
	fs.StringVar(&when, "time", "", "run time, RFC 3339 (default: now)")
	fs.StringVar(&outDir, "out-dir", "", "write README.md and trend.svg here (required)")
	fs.StringVar(&repoURL, "repo-url", "", "repository URL for commit links, e.g. https://github.com/org/repo")
	fs.IntVar(&points, "points", 60, "how many recent runs to chart")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if historyPath == "" || outDir == "" {
		return usageError{errors.New("-history and -out-dir are required")}
	}
	if reportPath != "" && commit == "" {
		return usageError{errors.New("-commit is required with -report")}
	}
	if points < 1 {
		return usageError{errors.New("-points must be at least 1")}
	}
	runTime := time.Now()
	if when != "" {
		t, err := time.Parse(time.RFC3339, when)
		if err != nil {
			return usageError{fmt.Errorf("invalid -time: %w", err)}
		}
		runTime = t
	}

	if reportPath != "" {
		rep, err := readFile(reportPath, score.ReadJSON)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(historyPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec // G302: the history is published
		if err != nil {
			return err
		}
		err = trend.Append(f, trend.FromReport(rep, trend.Meta{Time: runTime, Commit: commit, RunURL: runURL, Passed: passed}))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("appending to %s: %w", historyPath, err)
		}
	}

	entries, err := readFile(historyPath, trend.Read)
	if errors.Is(err, os.ErrNotExist) {
		entries, err = nil, nil
	}
	if err != nil {
		return err
	}
	recent := trend.Last(entries, points)
	if err := os.MkdirAll(outDir, 0o755); err != nil { //nolint:gosec // G301: the dashboard is published
		return err
	}
	if err := writeOutput(filepath.Join(outDir, "trend.svg"), nil, trend.RenderSVG(recent, trend.Detectors(recent))); err != nil {
		return err
	}
	readme, closeReadme, err := simcli.OpenOutput(filepath.Join(outDir, "README.md"), nil)
	if err != nil {
		return err
	}
	err = trend.RenderMarkdown(readme, recent, trend.MarkdownOptions{RepoURL: repoURL, ChartPath: "trend.svg", RecentRuns: 30})
	if cerr := closeReadme(); err == nil {
		err = cerr
	}
	return err
}
