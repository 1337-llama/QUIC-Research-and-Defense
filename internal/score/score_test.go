package score

import (
	"bytes"
	"encoding/json"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/detect"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/eve"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/groundtruth"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/profile"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/zeeklog"
)

var t0 = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func sess(id uint64, label profile.Label, local, remote string, start, end time.Duration) groundtruth.Record {
	return groundtruth.Record{
		Kind: groundtruth.KindSession, RunID: "r", Profile: "p", Label: label, SessionID: id,
		Local: ap(local), Remote: ap(remote), Start: t0.Add(start), End: t0.Add(end),
	}
}

func alert(det, a, b string, at time.Duration) Alert {
	return Alert{Detector: det, TS: t0.Add(at), A: ap(a), B: ap(b)}
}

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestScoreConfusionMatrix(t *testing.T) {
	t.Parallel()
	sessions := []groundtruth.Record{
		sess(1, profile.LabelMalicious, "10.0.0.30:5001", "10.0.0.10:443", 0, time.Minute),
		sess(2, profile.LabelMalicious, "10.0.0.30:5002", "10.0.0.10:443", 0, time.Minute),
		sess(3, profile.LabelMalicious, "10.0.0.30:5003", "10.0.0.10:443", 0, time.Minute),
		sess(4, profile.LabelBenign, "10.0.0.40:6001", "10.0.0.20:443", 0, time.Minute),
		sess(5, profile.LabelBenign, "10.0.0.40:6002", "10.0.0.20:443", 0, time.Minute),
	}
	alerts := []Alert{
		alert("d1", "10.0.0.30:5001", "10.0.0.10:443", 10*time.Second),
		alert("d1", "10.0.0.30:5001", "10.0.0.10:443", 20*time.Second), // duplicate hit on session 1
		alert("d1", "10.0.0.10:443", "10.0.0.30:5002", 30*time.Second), // reversed direction
		alert("d1", "10.0.0.40:6001", "10.0.0.20:443", 40*time.Second), // benign: FP
		alert("d1", "10.9.9.9:1", "10.0.0.20:443", 40*time.Second),     // matches nothing
		alert("d2", "10.0.0.30:5003", "10.0.0.10:443", 50*time.Second),
	}
	rep, err := Score(sessions, alerts, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Sessions != 5 || rep.Malicious != 3 || rep.Benign != 2 {
		t.Fatalf("totals = %+v", rep)
	}
	if rep.Results[0].Detector != AnyDetector || rep.Results[1].Detector != "d1" || rep.Results[2].Detector != "d2" {
		t.Fatalf("order = %+v", rep.Results)
	}

	d1, _ := rep.Result("d1")
	if d1.Alerts != 5 || d1.TP != 2 || d1.FN != 1 || d1.FP != 1 || d1.TN != 1 || d1.Unmatched != 1 {
		t.Errorf("d1 = %+v", d1)
	}
	if !approx(d1.Precision, 2.0/3) || !approx(d1.Recall, 2.0/3) || !approx(d1.F1, 2.0/3) {
		t.Errorf("d1 metrics = %+v", d1)
	}
	d2, _ := rep.Result("d2")
	if d2.TP != 1 || d2.FN != 2 || d2.FP != 0 || !approx(d2.Precision, 1) || !approx(d2.Recall, 1.0/3) {
		t.Errorf("d2 = %+v", d2)
	}
	anyRes, _ := rep.Result(AnyDetector)
	if anyRes.Alerts != 6 || anyRes.TP != 3 || anyRes.FN != 0 || anyRes.FP != 1 || anyRes.Unmatched != 1 || !approx(anyRes.Recall, 1) {
		t.Errorf("any = %+v", anyRes)
	}
	if _, ok := rep.Result("nope"); ok {
		t.Error("Result found a missing detector")
	}
}

func TestTimeWindowAndTolerance(t *testing.T) {
	t.Parallel()
	s := []groundtruth.Record{sess(1, profile.LabelMalicious, "10.0.0.30:5001", "10.0.0.10:443", time.Minute, 2*time.Minute)}
	early := alert("d", "10.0.0.30:5001", "10.0.0.10:443", 57*time.Second)
	late := alert("d", "10.0.0.30:5001", "10.0.0.10:443", 2*time.Minute+3*time.Second)

	rep, _ := Score(s, []Alert{early, late}, Options{})
	if r, _ := rep.Result("d"); r.TP != 0 || r.Unmatched != 2 {
		t.Errorf("no tolerance: %+v", r)
	}
	rep, _ = Score(s, []Alert{early, late}, Options{Tolerance: DefaultTolerance})
	if r, _ := rep.Result("d"); r.TP != 1 || r.Unmatched != 0 {
		t.Errorf("with tolerance: %+v", r)
	}
	if _, err := Score(s, nil, Options{Tolerance: -1}); err == nil {
		t.Error("negative tolerance accepted")
	}
}

func TestEndpointMatching(t *testing.T) {
	t.Parallel()
	tests := []struct {
		truth, seen string
		want        bool
	}{
		{"10.0.0.1:443", "10.0.0.1:443", true},
		{"10.0.0.1:443", "10.0.0.1:444", false},
		{"10.0.0.1:443", "10.0.0.2:443", false},
		{"0.0.0.0:5000", "172.28.0.30:5000", true}, // wildcard bind address
		{"[::]:5000", "172.28.0.30:5000", true},
		{"0.0.0.0:5000", "172.28.0.30:5001", false},
		{"[::ffff:10.0.0.1]:443", "10.0.0.1:443", true},
	}
	for _, tc := range tests {
		if got := endpointMatch(ap(tc.truth), ap(tc.seen)); got != tc.want {
			t.Errorf("endpointMatch(%s, %s) = %v", tc.truth, tc.seen, got)
		}
	}
	if endpointMatch(netip.AddrPort{}, ap("10.0.0.1:443")) || endpointMatch(ap("10.0.0.1:443"), netip.AddrPort{}) {
		t.Error("zero endpoints must never match")
	}
}

func TestScoreRejectsNonSessionRecords(t *testing.T) {
	t.Parallel()
	r := sess(1, profile.LabelMalicious, "10.0.0.1:1", "10.0.0.2:443", 0, time.Second)
	r.Kind = groundtruth.KindBeacon
	if _, err := Score([]groundtruth.Record{r}, nil, Options{}); err == nil {
		t.Fatal("beacon record accepted as a session")
	}
}

func TestNoAlertsYieldsZeroMetrics(t *testing.T) {
	t.Parallel()
	rep, err := Score([]groundtruth.Record{sess(1, profile.LabelMalicious, "10.0.0.1:1", "10.0.0.2:443", 0, time.Second)}, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	anyRes, _ := rep.Result(AnyDetector)
	if anyRes.FN != 1 || anyRes.Precision != 0 || anyRes.Recall != 0 || anyRes.F1 != 0 {
		t.Errorf("any = %+v", anyRes)
	}
}

func TestConverters(t *testing.T) {
	t.Parallel()
	d := FromDetect([]detect.Alert{{Detector: "long-connection", TS: t0, Orig: ap("10.0.0.1:1"), Resp: ap("10.0.0.2:443")}})
	e := FromEVE([]eve.Alert{{Signature: "Uncommon QUIC version", TS: t0, Src: ap("10.0.0.1:1"), Dst: ap("10.0.0.2:443")}})
	n := FromNotices([]zeeklog.Notice{{Note: "QUICHunt::Long_QUIC_Connection", TS: t0, Endpoints: zeeklog.Endpoints{Orig: ap("10.0.0.1:1"), Resp: ap("10.0.0.2:443")}}})
	if d[0].Detector != "long-connection" || e[0].Detector != "suricata:Uncommon QUIC version" || n[0].Detector != "zeek:QUICHunt::Long_QUIC_Connection" {
		t.Errorf("names: %q %q %q", d[0].Detector, e[0].Detector, n[0].Detector)
	}
	for _, a := range [][]Alert{d, e, n} {
		if a[0].A != ap("10.0.0.1:1") || a[0].B != ap("10.0.0.2:443") || !a[0].TS.Equal(t0) {
			t.Errorf("converted = %+v", a[0])
		}
	}
}

func TestWriters(t *testing.T) {
	t.Parallel()
	rep, _ := Score(
		[]groundtruth.Record{sess(1, profile.LabelMalicious, "10.0.0.1:1", "10.0.0.2:443", 0, time.Minute)},
		[]Alert{alert("long-connection", "10.0.0.1:1", "10.0.0.2:443", time.Second)}, Options{})
	var txt bytes.Buffer
	if err := WriteText(&txt, rep); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sessions: 1 (malicious 1, benign 0)", "long-connection", "1.000"} {
		if !strings.Contains(txt.String(), want) {
			t.Errorf("text output missing %q:\n%s", want, txt.String())
		}
	}
	var js bytes.Buffer
	if err := WriteJSON(&js, rep); err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(js.Bytes(), &back); err != nil || len(back.Results) != 2 || back.Results[1].Recall != 1 {
		t.Errorf("json round trip = %+v, %v", back, err)
	}
}

func TestParseRequirement(t *testing.T) {
	t.Parallel()
	good := map[string]Requirement{
		"(any):recall>=0.95":                            {AnyDetector, "recall", 0.95},
		"long-connection:precision>=1":                  {"long-connection", "precision", 1},
		"zeek:QUICHunt::Long_QUIC_Connection:f1>= 0.5":  {"zeek:QUICHunt::Long_QUIC_Connection", "f1", 0.5},
		"suricata:Uncommon QUIC version:precision>=0.0": {"suricata:Uncommon QUIC version", "precision", 0},
	}
	for in, want := range good {
		got, err := ParseRequirement(in)
		if err != nil || got != want {
			t.Errorf("ParseRequirement(%q) = %+v, %v", in, got, err)
		}
		if back, err := ParseRequirement(got.String()); err != nil || back != got {
			t.Errorf("String round trip of %q = %+v, %v", in, back, err)
		}
	}
	for _, in := range []string{"", "recall>=1", ":recall>=1", "d:recall", "d:accuracy>=1", "d:recall>=x", "d:recall>=1.5", "d:>=1", "d:recall>=-0.1"} {
		if _, err := ParseRequirement(in); err == nil {
			t.Errorf("ParseRequirement(%q) accepted", in)
		}
	}
}

func TestCheck(t *testing.T) {
	t.Parallel()
	rep := Report{Results: []Result{{Detector: "d", Precision: 0.9, Recall: 0.5, F1: 0.64}}}
	reqs := []Requirement{
		{"d", "precision", 0.9},
		{"d", "recall", 0.6},
		{"d", "f1", 0.7},
		{"missing", "recall", 0.1},
	}
	errs := Check(rep, reqs)
	if len(errs) != 3 {
		t.Fatalf("errs = %v", errs)
	}
	if !strings.Contains(errs[0].Error(), "got 0.500") || !strings.Contains(errs[2].Error(), "no alerts") {
		t.Errorf("errs = %v", errs)
	}
}

func TestReadJSON(t *testing.T) {
	t.Parallel()
	rep := Report{Sessions: 2, Malicious: 1, Benign: 1, Results: []Result{{Detector: AnyDetector, TP: 1, Precision: 1, Recall: 1, F1: 1}}}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	back, err := ReadJSON(&buf)
	if err != nil || back.Sessions != 2 || len(back.Results) != 1 || back.Results[0].F1 != 1 {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
	for name, in := range map[string]string{
		"not json":      "[",
		"unknown field": `{"sessions":0,"extra":1}`,
		"inconsistent":  `{"sessions":3,"malicious":1,"benign":1}`,
	} {
		if _, err := ReadJSON(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
