package grade

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/groundtruth"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/profile"
)

var t0 = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

func session(local, prof string, label profile.Label) groundtruth.Record {
	return groundtruth.Record{
		Kind: groundtruth.KindSession, RunID: prof, Profile: prof, Label: label, SessionID: 1,
		Local: netip.MustParseAddrPort(local), Remote: netip.MustParseAddrPort("172.28.0.10:443"),
		Start: t0, End: t0.Add(time.Second),
	}
}

func truth() []groundtruth.Record {
	return []groundtruth.Record{
		session("172.28.0.130:4000", "merlin-like", profile.LabelMalicious),
		session("172.28.0.130:4001", "merlin-like", profile.LabelMalicious),
		session("172.28.0.140:4000", "low-and-slow", profile.LabelMalicious),
		session("172.28.0.150:4000", "browser-like", profile.LabelBenign),
		session("172.28.0.160:4000", "chromium", profile.LabelBenign),
		// A host with mixed traffic counts as malicious.
		session("172.28.0.170:4000", "browser-like", profile.LabelBenign),
		session("172.28.0.170:4001", "quicagent-like", profile.LabelMalicious),
	}
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestParseAnswers(t *testing.T) {
	t.Parallel()
	in := `# my answers
172.28.0.130   # long connection, steady bursts

  172.28.0.140
172.28.0.130
::ffff:172.28.0.150 # mapped form is normalized
`
	got, err := ParseAnswers(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := addrs("172.28.0.130", "172.28.0.140", "172.28.0.150")
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("answer %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestParseAnswersErrors(t *testing.T) {
	t.Parallel()
	for name, in := range map[string]string{
		"not an IP":    "172.28.0.1\nmerlin\n",
		"two per line": "172.28.0.1 172.28.0.2\n",
	} {
		_, err := ParseAnswers(strings.NewReader(in))
		if err == nil || !strings.Contains(err.Error(), "line ") {
			t.Errorf("%s: err = %v, want a line-numbered error", name, err)
		}
	}
	if _, err := ParseAnswers(iotest.ErrReader(iotest.ErrTimeout)); err == nil {
		t.Error("read error not returned")
	}
	var many strings.Builder
	for i := range MaxAnswers + 1 {
		many.WriteString(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String() + "\n")
	}
	if _, err := ParseAnswers(strings.NewReader(many.String())); err == nil {
		t.Error("answer limit not enforced")
	}
}

func TestGrade(t *testing.T) {
	t.Parallel()
	// Found merlin and the mixed host, missed low-and-slow, flagged the
	// real browser, and also listed the C2 server.
	res, err := Grade(truth(), addrs("172.28.0.130", "172.28.0.170", "172.28.0.160", "172.28.0.10"))
	if err != nil {
		t.Fatal(err)
	}
	if res.TP != 2 || res.FN != 1 || res.FP != 1 || res.TN != 1 || res.MaliciousTotal != 3 {
		t.Fatalf("counts = %+v", res)
	}
	if res.Precision != 2.0/3 || res.Recall != 2.0/3 || res.Score != 67 {
		t.Errorf("metrics = %v %v %v %d", res.Precision, res.Recall, res.F1, res.Score)
	}
	if len(res.NotClients) != 1 || res.NotClients[0] != netip.MustParseAddr("172.28.0.10") {
		t.Errorf("NotClients = %v", res.NotClients)
	}
	want := map[string]Outcome{
		"172.28.0.130": TruePositive, "172.28.0.140": FalseNegative, "172.28.0.150": TrueNegative,
		"172.28.0.160": FalsePositive, "172.28.0.170": TruePositive,
	}
	if len(res.Clients) != len(want) {
		t.Fatalf("clients = %+v", res.Clients)
	}
	for i, c := range res.Clients {
		if c.Outcome != want[c.Addr.String()] {
			t.Errorf("%s: %s, want %s", c.Addr, c.Outcome, want[c.Addr.String()])
		}
		if i > 0 && res.Clients[i-1].Addr.Compare(c.Addr) >= 0 {
			t.Error("clients are not sorted by address")
		}
	}
	mixed := res.Clients[4]
	if mixed.Label != profile.LabelMalicious || mixed.Sessions != 2 || strings.Join(mixed.Profiles, ",") != "browser-like,quicagent-like" {
		t.Errorf("mixed host = %+v", mixed)
	}
}

func TestGradeEdgeCases(t *testing.T) {
	t.Parallel()
	perfect, err := Grade(truth(), addrs("172.28.0.130", "172.28.0.140", "172.28.0.170"))
	if err != nil || perfect.Score != 100 || perfect.FP != 0 {
		t.Fatalf("perfect = %+v, %v", perfect, err)
	}
	none, err := Grade(truth(), nil)
	if err != nil || none.Score != 0 || none.Precision != 0 || none.FN != 3 {
		t.Fatalf("empty answers = %+v, %v", none, err)
	}
	if _, err := Grade(nil, nil); err == nil {
		t.Error("empty truth accepted")
	}
	beacon := session("172.28.0.130:4000", "merlin-like", profile.LabelMalicious)
	beacon.Kind = groundtruth.KindBeacon
	if _, err := Grade([]groundtruth.Record{beacon}, nil); err == nil {
		t.Error("beacon record accepted as a session")
	}
}

func TestWriteText(t *testing.T) {
	t.Parallel()
	res, err := Grade(truth(), addrs("172.28.0.130", "172.28.0.10"))
	if err != nil {
		t.Fatal(err)
	}
	var hidden bytes.Buffer
	if err := WriteText(&hidden, res, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hidden.String(), "score: 50/100") || !strings.Contains(hidden.String(), "found 1 of 3") ||
		!strings.Contains(hidden.String(), "not graded (not a client in this exercise): 172.28.0.10") {
		t.Errorf("summary:\n%s", hidden.String())
	}
	for _, secret := range []string{"merlin-like", "low-and-slow", "172.28.0.140"} {
		if strings.Contains(hidden.String(), secret) {
			t.Errorf("unrevealed output leaks %q:\n%s", secret, hidden.String())
		}
	}
	var shown bytes.Buffer
	if err := WriteText(&shown, res, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(shown.String(), "172.28.0.140") || !strings.Contains(shown.String(), "low-and-slow") ||
		!strings.Contains(shown.String(), "FN") {
		t.Errorf("debrief:\n%s", shown.String())
	}
}

func TestWriteJSON(t *testing.T) {
	t.Parallel()
	res, _ := Grade(truth(), addrs("172.28.0.130"))
	var buf bytes.Buffer
	if err := WriteJSON(&buf, res); err != nil {
		t.Fatal(err)
	}
	var back Result
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Score != res.Score || len(back.Clients) != len(res.Clients) || back.Clients[0].Outcome != TruePositive {
		t.Errorf("round trip = %+v", back)
	}
}
