package profile

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validProfile() Profile {
	return Profile{
		Name:       "test-profile",
		Label:      LabelMalicious,
		Schedule:   Schedule{Distribution: DistJitter, Interval: Duration(time.Second), Jitter: 0.2},
		Connection: Connection{Mode: ModePersistent},
		Request:    Request{Method: "POST", Path: "/beacon", MinBodyBytes: 10, MaxBodyBytes: 100},
		QUIC:       QUIC{MaxIdleTimeout: Duration(30 * time.Second), KeepAlivePeriod: Duration(10 * time.Second)},
	}
}

func TestBuiltinProfilesAreValid(t *testing.T) {
	t.Parallel()
	ps := Builtin()
	if len(ps) == 0 {
		t.Fatal("no built-in profiles")
	}
	seen := map[string]bool{}
	labels := map[Label]int{}
	for _, p := range ps {
		if err := p.Validate(); err != nil {
			t.Errorf("built-in %s: %v", p.Name, err)
		}
		if seen[p.Name] {
			t.Errorf("duplicate built-in name %q", p.Name)
		}
		seen[p.Name] = true
		labels[p.Label]++
		if p.Description == "" {
			t.Errorf("built-in %s has no description", p.Name)
		}
	}
	if labels[LabelBenign] == 0 || labels[LabelMalicious] == 0 {
		t.Errorf("built-ins must include both benign and malicious profiles, got %v", labels)
	}
}

func TestBuiltinReturnsSortedCopies(t *testing.T) {
	t.Parallel()
	a := Builtin()
	for i := 1; i < len(a); i++ {
		if a[i-1].Name >= a[i].Name {
			t.Fatalf("not sorted: %q before %q", a[i-1].Name, a[i].Name)
		}
	}
	a[0].Name = "mutated"
	if Builtin()[0].Name == "mutated" {
		t.Fatal("Builtin must return copies")
	}
}

func TestLookup(t *testing.T) {
	t.Parallel()
	p, err := Lookup("merlin-like")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if p.Connection.Mode != ModePersistent {
		t.Errorf("merlin-like mode = %s, want persistent", p.Connection.Mode)
	}
	_, err = Lookup("nope")
	if err == nil || !strings.Contains(err.Error(), "browser-like") {
		t.Errorf("Lookup(nope) error should list built-ins, got %v", err)
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*Profile)
		wantErr string
	}{
		{"valid", func(*Profile) {}, ""},
		{"bad name", func(p *Profile) { p.Name = "Bad Name" }, "name"},
		{"empty name", func(p *Profile) { p.Name = "" }, "name"},
		{"bad label", func(p *Profile) { p.Label = "evil" }, "label"},
		{"interval too small", func(p *Profile) { p.Schedule.Interval = Duration(time.Millisecond) }, "interval"},
		{"interval too large", func(p *Profile) { p.Schedule.Interval = Duration(48 * time.Hour) }, "interval"},
		{"jitter negative", func(p *Profile) { p.Schedule.Jitter = -0.1 }, "jitter"},
		{"jitter one", func(p *Profile) { p.Schedule.Jitter = 1 }, "jitter"},
		{"exponential with jitter", func(p *Profile) { p.Schedule.Distribution = DistExponential }, "jitter must be 0"},
		{"exponential ok", func(p *Profile) { p.Schedule.Distribution = DistExponential; p.Schedule.Jitter = 0 }, ""},
		{"bad distribution", func(p *Profile) { p.Schedule.Distribution = "gaussian" }, "distribution"},
		{"rotate without age", func(p *Profile) { p.Connection.Mode = ModeRotate }, "rotate_after must be positive"},
		{"rotate ok", func(p *Profile) {
			p.Connection.Mode = ModeRotate
			p.Connection.RotateAfter = Duration(time.Minute)
		}, ""},
		{"age without rotate", func(p *Profile) { p.Connection.RotateAfter = Duration(time.Minute) }, "only valid in rotate mode"},
		{"bad mode", func(p *Profile) { p.Connection.Mode = "sometimes" }, "connection.mode"},
		{"bad method", func(p *Profile) { p.Request.Method = "PUT" }, "method"},
		{"get with body", func(p *Profile) { p.Request.Method = "GET" }, "must be 0 for GET"},
		{"get ok", func(p *Profile) {
			p.Request.Method = "GET"
			p.Request.MinBodyBytes, p.Request.MaxBodyBytes = 0, 0
		}, ""},
		{"relative path", func(p *Profile) { p.Request.Path = "beacon" }, "path"},
		{"path whitespace", func(p *Profile) { p.Request.Path = "/a b" }, "path"},
		{"min over max", func(p *Profile) { p.Request.MinBodyBytes = 200 }, "body sizes"},
		{"negative min", func(p *Profile) { p.Request.MinBodyBytes = -1 }, "body sizes"},
		{"max too big", func(p *Profile) { p.Request.MaxBodyBytes = MaxBodyBytes + 1 }, "body sizes"},
		{"ua newline", func(p *Profile) { p.Request.UserAgent = "a\r\nX-Evil: 1" }, "user_agent"},
		{"negative timeout", func(p *Profile) { p.QUIC.HandshakeIdleTimeout = Duration(-time.Second) }, "handshake_idle_timeout"},
		{"keepalive not shorter", func(p *Profile) { p.QUIC.KeepAlivePeriod = p.QUIC.MaxIdleTimeout }, "keep_alive_period"},
		{"window too big", func(p *Profile) { p.QUIC.InitialStreamReceiveWindow = MaxFlowWindow + 1 }, "receive windows"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := validProfile()
			tc.mutate(&p)
			err := p.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateReportsAllProblems(t *testing.T) {
	t.Parallel()
	p := validProfile()
	p.Name = ""
	p.Label = ""
	p.Request.Method = "PATCH"
	err := p.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"name", "label", "method"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("joined error missing %q: %v", want, err)
		}
	}
}

func TestLoadRoundTrip(t *testing.T) {
	t.Parallel()
	for _, want := range Builtin() {
		data, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("marshal %s: %v", want.Name, err)
		}
		got, err := Load(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("Load %s: %v\n%s", want.Name, err, data)
		}
		if got != want {
			t.Errorf("round trip mismatch for %s:\n got %+v\nwant %+v", want.Name, got, want)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"not json":         `nope`,
		"unknown field":    `{"name":"x","label":"benign","bogus":1}`,
		"numeric duration": `{"name":"x","schedule":{"interval":30}}`,
		"bad duration":     `{"name":"x","schedule":{"interval":"thirty"}}`,
		"trailing data":    `{"name":"x"} {}`,
		"fails validation": `{"name":"x","label":"benign"}`,
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Load(strings.NewReader(in)); err == nil {
				t.Fatalf("Load(%s) succeeded, want error", in)
			}
		})
	}
}

func TestDurationJSON(t *testing.T) {
	t.Parallel()
	d := Duration(90 * time.Second)
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"1m30s"` {
		t.Fatalf("marshal = %s", b)
	}
	var back Duration
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back != d || back.Std() != 90*time.Second || back.String() != "1m30s" {
		t.Fatalf("round trip = %v", back)
	}
}

func FuzzLoad(f *testing.F) {
	for _, p := range Builtin() {
		b, _ := json.Marshal(p)
		f.Add(b)
	}
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Load(bytes.NewReader(data))
		if err != nil {
			return
		}
		// Anything Load accepts must be valid and must survive a round trip.
		if verr := p.Validate(); verr != nil {
			t.Fatalf("Load returned an invalid profile: %v", verr)
		}
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := Load(bytes.NewReader(b)); err != nil {
			t.Fatalf("re-load failed: %v", err)
		}
	})
}
