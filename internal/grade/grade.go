// Package grade scores an analyst's answers to a lab exercise.
//
// An exercise asks one question: which client hosts are beaconing? The
// analyst works from the capture and sensor logs alone, with the ground
// truth held back, and writes down the client IPs they believe are
// compromised. Grade compares that list with the ground truth at host level:
// a client is malicious if any of its sessions is.
//
// Host level is deliberate. It is how an analyst reports a finding
// ("10.1.2.3 is beaconing"), and it does not reward flagging every
// connection of a noisy host separately.
package grade

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/groundtruth"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/profile"
)

// MaxAnswers bounds an answers file, which is written by hand.
const MaxAnswers = 10_000

// ParseAnswers reads one client IP per line. Blank lines are skipped, and
// anything after a '#' is a comment, so analysts can note their reasoning:
//
//	172.28.0.131   # regular 30s bursts inside one long connection
//
// Duplicates are ignored. Errors name the offending line.
func ParseAnswers(r io.Reader) ([]netip.Addr, error) {
	sc := bufio.NewScanner(r)
	seen := make(map[netip.Addr]bool)
	var out []netip.Addr
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) > 1 {
			return nil, fmt.Errorf("line %d: want one IP address per line (put notes after '#'), got %q", n, strings.TrimSpace(line))
		}
		a, err := netip.ParseAddr(fields[0])
		if err != nil {
			return nil, fmt.Errorf("line %d: %q is not an IP address", n, fields[0])
		}
		a = a.Unmap()
		if seen[a] {
			continue
		}
		if len(out) == MaxAnswers {
			return nil, fmt.Errorf("more than %d answers", MaxAnswers)
		}
		seen[a] = true
		out = append(out, a)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Outcome classifies one client.
type Outcome string

// Outcomes.
const (
	TruePositive  Outcome = "TP"
	FalsePositive Outcome = "FP"
	FalseNegative Outcome = "FN"
	TrueNegative  Outcome = "TN"
)

// Client is the verdict for one client host.
type Client struct {
	Addr     netip.Addr    `json:"addr"`
	Label    profile.Label `json:"label"`
	Profiles []string      `json:"profiles"`
	Sessions int           `json:"sessions"`
	Flagged  bool          `json:"flagged"`
	Outcome  Outcome       `json:"outcome"`
}

// Result is a graded answer sheet.
type Result struct {
	Clients        []Client     `json:"clients"`
	TP             int          `json:"tp"`
	FP             int          `json:"fp"`
	FN             int          `json:"fn"`
	TN             int          `json:"tn"`
	Precision      float64      `json:"precision"`
	Recall         float64      `json:"recall"`
	F1             float64      `json:"f1"`
	Score          int          `json:"score"`
	NotClients     []netip.Addr `json:"not_clients,omitempty"`
	MaliciousTotal int          `json:"malicious_total"`
}

// Grade scores the flagged addresses against session ground truth.
// Addresses that are not clients in the ground truth (for example a server
// address) are listed in NotClients and do not affect the score.
func Grade(sessions []groundtruth.Record, flagged []netip.Addr) (Result, error) {
	if len(sessions) == 0 {
		return Result{}, errors.New("grade: no ground-truth sessions")
	}
	byAddr := make(map[netip.Addr]*Client)
	var order []netip.Addr
	for _, s := range sessions {
		if s.Kind != groundtruth.KindSession {
			return Result{}, fmt.Errorf("grade: record for run %q is a %q, not a session", s.RunID, s.Kind)
		}
		a := s.Local.Addr().Unmap()
		c, ok := byAddr[a]
		if !ok {
			c = &Client{Addr: a, Label: profile.LabelBenign}
			byAddr[a] = c
			order = append(order, a)
		}
		c.Sessions++
		if s.Label == profile.LabelMalicious {
			c.Label = profile.LabelMalicious
		}
		if !slices.Contains(c.Profiles, s.Profile) {
			c.Profiles = append(c.Profiles, s.Profile)
		}
	}

	var res Result
	for _, a := range flagged {
		if c, ok := byAddr[a.Unmap()]; ok {
			c.Flagged = true
		} else {
			res.NotClients = append(res.NotClients, a)
		}
	}
	slices.SortFunc(order, func(x, y netip.Addr) int { return x.Compare(y) })
	for _, a := range order {
		c := byAddr[a]
		slices.Sort(c.Profiles)
		mal := c.Label == profile.LabelMalicious
		switch {
		case mal && c.Flagged:
			c.Outcome = TruePositive
			res.TP++
		case mal:
			c.Outcome = FalseNegative
			res.FN++
		case c.Flagged:
			c.Outcome = FalsePositive
			res.FP++
		default:
			c.Outcome = TrueNegative
			res.TN++
		}
		res.Clients = append(res.Clients, *c)
	}
	res.MaliciousTotal = res.TP + res.FN
	res.Precision = ratio(res.TP, res.TP+res.FP)
	res.Recall = ratio(res.TP, res.TP+res.FN)
	if res.Precision+res.Recall > 0 {
		res.F1 = 2 * res.Precision * res.Recall / (res.Precision + res.Recall)
	}
	res.Score = int(math.Round(100 * res.F1))
	return res, nil
}

func ratio(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}

// WriteText writes a human-readable result. With reveal, it includes the
// per-client debrief (labels and profiles); without, only the counts, so an
// analyst can retry without seeing the answers.
func WriteText(w io.Writer, r Result, reveal bool) error {
	fmt.Fprintf(w, "score: %d/100  (precision %.3f, recall %.3f, F1 %.3f)\n", r.Score, r.Precision, r.Recall, r.F1)
	fmt.Fprintf(w, "found %d of %d beaconing hosts; %d benign hosts flagged\n", r.TP, r.MaliciousTotal, r.FP)
	if len(r.NotClients) > 0 {
		fmt.Fprintf(w, "not graded (not a client in this exercise): %s\n", joinAddrs(r.NotClients))
	}
	if !reveal {
		return nil
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CLIENT\tYOU\tTRUTH\tRESULT\tSESSIONS\tPROFILES")
	for _, c := range r.Clients {
		you := "-"
		if c.Flagged {
			you = "flagged"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n", c.Addr, you, c.Label, c.Outcome, c.Sessions, strings.Join(c.Profiles, ","))
	}
	return tw.Flush()
}

// WriteJSON writes the result as indented JSON.
func WriteJSON(w io.Writer, r Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func joinAddrs(as []netip.Addr) string {
	s := make([]string, len(as))
	for i, a := range as {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}
