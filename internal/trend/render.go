package trend

import (
	"bytes"
	"fmt"
	"html"
	"io"
	"math"
	"strings"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/score"
)

// Chart geometry, in SVG user units.
const (
	panelW   = 360
	panelH   = 150
	gapX     = 24
	gapY     = 20
	columns  = 2
	padTop   = 56 // title and legend
	plotL    = 34 // room for y tick labels
	plotR    = 96 // room for end labels
	plotT    = 26 // panel title
	plotB    = 22 // x labels
	labelGap = 12 // minimum vertical distance between end labels
)

// The two series use the first two slots of the validated categorical
// palette (blue, orange), stepped separately for light and dark surfaces.
// Text uses the ink tokens, never the series colors. Precision's light-mode
// orange is under 3:1 against white, so both lines are direct-labeled with
// their values and the page carries a table view.
// Plain class rules rather than CSS variables, so renderers without custom
// property support (rsvg, some viewers) draw the same chart.
const svgStyle = `
  text { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; fill: #666666; font-size: 11px; font-variant-numeric: tabular-nums; }
  .bg { fill: #ffffff; }
  .title { fill: #191919; font-size: 15px; font-weight: 600; }
  .panel-title { fill: #191919; font-size: 12px; font-weight: 600; }
  .grid { stroke: #e7e7e7; stroke-width: 1; }
  .axis { stroke: #c2c2c2; stroke-width: 1; }
  .line { fill: none; stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
  .recall { stroke: #257de0; }
  .precision { stroke: #f47230; }
  .dot { stroke: #ffffff; stroke-width: 2; }
  .dot.recall { fill: #257de0; }
  .dot.precision { fill: #f47230; }
  .hit { fill: transparent; stroke: none; }
  @media (prefers-color-scheme: dark) {
    text { fill: #9c9c9c; }
    .bg { fill: #191919; }
    .title, .panel-title { fill: #efefef; }
    .grid { stroke: #303030; }
    .axis { stroke: #474747; }
    .recall { stroke: #338ced; }
    .precision { stroke: #e76624; }
    .dot { stroke: #191919; }
    .dot.recall { fill: #338ced; }
    .dot.precision { fill: #e76624; }
  }
`

type series struct {
	name, class string
	value       func(Metrics) float64
}

// allSeries is in drawing order: recall is drawn last, on top, because the
// lines often coincide at 1.0 and recall is the one that moves.
var allSeries = []series{
	{"precision", "precision", func(m Metrics) float64 { return m.Precision }},
	{"recall", "recall", func(m Metrics) float64 { return m.Recall }},
}

// RenderSVG draws one small panel per detector, each with recall and
// precision over the given runs. Separate panels keep every line readable:
// on one shared chart, detectors that all sit at 1.0 would hide each other.
func RenderSVG(entries []Entry, detectors []string) []byte {
	var b bytes.Buffer
	rows := (len(detectors) + columns - 1) / columns
	width := columns*panelW + (columns-1)*gapX
	height := padTop + max(rows, 1)*(panelH+gapY)
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-labelledby="t d">`,
		width, height, width, height)
	fmt.Fprintf(&b, "<title id=\"t\">Detection lab: precision and recall per detector</title>")
	fmt.Fprintf(&b, "<desc id=\"d\">%d lab runs. One panel per detector; blue is recall, orange is precision, both from 0 to 1.</desc>", len(entries))
	fmt.Fprintf(&b, "<style>%s</style><g>", svgStyle)
	fmt.Fprintf(&b, `<rect class="bg" width="%d" height="%d"/>`, width, height)
	fmt.Fprintf(&b, `<text class="title" x="0" y="18">Precision and recall per detector, %s</text>`, lastRuns(len(entries)))
	legend(&b, 0, 40)

	if len(entries) == 0 {
		fmt.Fprintf(&b, `<text x="0" y="%d">No lab runs recorded yet.</text>`, padTop+20)
	}
	for i, det := range detectors {
		x := (i % columns) * (panelW + gapX)
		y := padTop + (i/columns)*(panelH+gapY)
		panel(&b, entries, det, x, y)
	}
	b.WriteString("</g></svg>\n")
	return b.Bytes()
}

func legend(b *bytes.Buffer, x, y int) {
	for i := len(allSeries) - 1; i >= 0; i-- {
		s := allSeries[i]
		fmt.Fprintf(b, `<line class="line %s" x1="%d" y1="%d" x2="%d" y2="%d"/>`, s.class, x, y-4, x+16, y-4)
		fmt.Fprintf(b, `<text x="%d" y="%d">%s</text>`, x+22, y, titleCase(s.name))
		x += 100
	}
}

func panel(b *bytes.Buffer, entries []Entry, det string, x, y int) {
	l, r := x+plotL, x+panelW-plotR
	t, bot := y+plotT, y+panelH-plotB
	fmt.Fprintf(b, `<text class="panel-title" x="%d" y="%d">%s</text>`, x, y+14, esc(det))
	for _, v := range []float64{0, 0.5, 1} {
		gy := yAt(v, t, bot)
		class := "grid"
		if v == 0 {
			class = "axis"
		}
		fmt.Fprintf(b, `<line class="%s" x1="%d" y1="%.1f" x2="%d" y2="%.1f"/>`, class, l, gy, r, gy)
		fmt.Fprintf(b, `<text x="%d" y="%.1f" text-anchor="end">%s</text>`, l-6, gy+4, trimFloat(v))
	}
	if len(entries) > 0 {
		fmt.Fprintf(b, `<text x="%d" y="%d">%s</text>`, l, bot+16, entries[0].Time.Format(time.DateOnly))
		if len(entries) > 1 {
			fmt.Fprintf(b, `<text x="%d" y="%d" text-anchor="end">%s</text>`, r, bot+16, entries[len(entries)-1].Time.Format(time.DateOnly))
		}
	}

	type end struct {
		s    series
		v, y float64
		x    float64
	}
	var ends []end
	for _, s := range allSeries {
		var seg []string
		flush := func() {
			if len(seg) > 1 {
				fmt.Fprintf(b, `<polyline class="line %s" points="%s"/>`, s.class, strings.Join(seg, " "))
			}
			seg = seg[:0]
		}
		var last *end
		for i, e := range entries {
			m, ok := e.Detectors[det]
			if !ok {
				flush() // a run without this detector breaks the line
				continue
			}
			px, py := xAt(i, len(entries), l, r), yAt(s.value(m), t, bot)
			seg = append(seg, fmt.Sprintf("%.1f,%.1f", px, py))
			if i == len(entries)-1 {
				last = &end{s: s, v: s.value(m), y: py, x: px}
			}
		}
		flush()
		if last != nil {
			ends = append(ends, *last)
		}
	}
	// End dots and direct value labels, nudged apart when the two series
	// finish at (nearly) the same value.
	if len(ends) == 2 && math.Abs(ends[0].y-ends[1].y) < labelGap {
		mid := (ends[0].y + ends[1].y) / 2
		ends[0].y, ends[1].y = mid-labelGap/2, mid+labelGap/2
	}
	for _, e := range ends {
		dotY := yAt(e.v, t, bot)
		fmt.Fprintf(b, `<circle class="dot %s" cx="%.1f" cy="%.1f" r="4"/>`, e.s.class, e.x, dotY)
		fmt.Fprintf(b, `<text x="%.1f" y="%.1f">%s %.2f</text>`, e.x+10, e.y+4, e.s.name, e.v)
	}
	// Invisible per-run hit targets carry a native tooltip when the SVG is
	// opened directly. Markdown renderers show it as an image, so the page
	// also has a table view.
	for i, e := range entries {
		m, ok := e.Detectors[det]
		if !ok {
			continue
		}
		px := xAt(i, len(entries), l, r)
		w := math.Max(6, float64(r-l)/float64(max(len(entries), 1)))
		fmt.Fprintf(b, `<rect class="hit" x="%.1f" y="%d" width="%.1f" height="%d"><title>%s · %s&#10;recall %.3f · precision %.3f · %d alerts</title></rect>`,
			px-w/2, t, w, bot-t, e.Time.Format("2006-01-02 15:04 MST"), esc(shortSHA(e.Commit)), m.Recall, m.Precision, m.Alerts)
	}
}

func xAt(i, n, l, r int) float64 {
	if n <= 1 {
		return float64(r)
	}
	return float64(l) + float64(i)*float64(r-l)/float64(n-1)
}

func yAt(v float64, t, bot int) float64 {
	v = math.Max(0, math.Min(1, v))
	return float64(bot) - v*float64(bot-t)
}

func trimFloat(v float64) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.1f", v), "0"), ".")
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func esc(s string) string { return html.EscapeString(s) }

func shortSHA(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

// MarkdownOptions configures RenderMarkdown.
type MarkdownOptions struct {
	// RepoURL links commits, e.g. https://github.com/org/repo.
	RepoURL string
	// ChartPath is the chart's path relative to the page.
	ChartPath string
	// RecentRuns is how many runs the history table lists.
	RecentRuns int
}

// RenderMarkdown writes the dashboard page: the latest results, the chart,
// and a table of recent runs (the chart's table view).
func RenderMarkdown(w io.Writer, entries []Entry, opt MarkdownOptions) error {
	var b strings.Builder
	b.WriteString("# Detection lab results\n\n")
	b.WriteString("Nightly results of the Docker detection lab: every reference detection scored against simulator ground truth. ")
	b.WriteString("This branch is written by the `Lab end-to-end` workflow; don't edit it by hand.\n\n")
	if len(entries) == 0 {
		b.WriteString("No lab runs recorded yet.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}
	latest := entries[len(entries)-1]
	var prev *Entry
	if len(entries) > 1 {
		prev = &entries[len(entries)-2]
	}
	fmt.Fprintf(&b, "## Latest run\n\n%s, commit %s: gates %s. %d sessions (%d malicious, %d benign).",
		latest.Time.Format("2006-01-02 15:04 MST"), commitLink(opt.RepoURL, latest.Commit), passText(latest.Passed),
		latest.Sessions, latest.Malicious, latest.Benign)
	if latest.RunURL != "" {
		fmt.Fprintf(&b, " [Workflow run](%s).", latest.RunURL)
	}
	b.WriteString("\n\n| Detector | Precision | Recall | F1 | Recall change |\n|---|---:|---:|---:|---:|\n")
	for _, det := range Detectors(entries) {
		m := latest.Detectors[det]
		change := "new"
		if prev != nil {
			if pm, ok := prev.Detectors[det]; ok {
				change = signed(m.Recall - pm.Recall)
			}
		} else {
			change = "–"
		}
		fmt.Fprintf(&b, "| `%s` | %.3f | %.3f | %.3f | %s |\n", mdCell(det), m.Precision, m.Recall, m.F1, change)
	}
	if opt.ChartPath != "" {
		fmt.Fprintf(&b, "\n## Over time\n\n![Precision and recall per detector, %s](%s)\n", lastRuns(len(entries)), opt.ChartPath)
	}

	n := opt.RecentRuns
	if n <= 0 {
		n = 30
	}
	fmt.Fprintf(&b, "\n## Recent runs\n\nThe table view of the chart's combined score, newest first.\n\n")
	b.WriteString("| Time (UTC) | Commit | Gates | Sessions | `(any)` precision | `(any)` recall | Run |\n|---|---|---|---:|---:|---:|---|\n")
	recent := Last(entries, n)
	for i := len(recent) - 1; i >= 0; i-- {
		e := recent[i]
		anyM, ok := e.Detectors[score.AnyDetector]
		p, r := "–", "–"
		if ok {
			p, r = fmt.Sprintf("%.3f", anyM.Precision), fmt.Sprintf("%.3f", anyM.Recall)
		}
		run := "–"
		if e.RunURL != "" {
			run = fmt.Sprintf("[log](%s)", e.RunURL)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %s | %s | %s |\n",
			e.Time.Format("2006-01-02 15:04"), commitLink(opt.RepoURL, e.Commit), passText(e.Passed), e.Sessions, p, r, run)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func passText(ok bool) string {
	if ok {
		return "passed"
	}
	return "**failed**"
}

func signed(d float64) string {
	if math.Abs(d) < 0.0005 {
		return "0"
	}
	return fmt.Sprintf("%+.3f", d)
}

func commitLink(repo, sha string) string {
	short := "`" + mdCell(shortSHA(sha)) + "`"
	if repo == "" || !isHex(sha) {
		return short
	}
	return fmt.Sprintf("[%s](%s/commit/%s)", short, strings.TrimRight(repo, "/"), sha)
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

// mdCell keeps a value from breaking out of a table cell or code span.
func mdCell(s string) string {
	return strings.NewReplacer("|", `\|`, "`", "'", "\n", " ", "\r", " ").Replace(s)
}

func lastRuns(n int) string {
	if n == 1 {
		return "last run"
	}
	return fmt.Sprintf("last %d runs", n)
}
