package labeling

import (
	"net/netip"
	"testing"
	"time"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/profile"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/zeeklog"
)

var t0 = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

func conn(orig, resp string, at time.Duration, svc ...string) zeeklog.Conn {
	return zeeklog.Conn{
		UID: orig, TS: t0.Add(at), Duration: 2 * time.Second, Service: svc,
		Endpoints: zeeklog.Endpoints{Orig: netip.MustParseAddrPort(orig), Resp: netip.MustParseAddrPort(resp)},
	}
}

func spec() Spec {
	return Spec{
		Hosts: []netip.Addr{netip.MustParseAddr("172.28.0.50")}, Services: []string{"quic"},
		Label: profile.LabelBenign, Profile: "chromium", RunID: "chromium",
	}
}

func TestFromConns(t *testing.T) {
	t.Parallel()
	conns := []zeeklog.Conn{
		conn("172.28.0.50:40000", "172.28.0.20:443", 0, "quic", "ssl"),
		conn("172.28.0.50:40001", "172.28.0.2:53", time.Second, "dns"),      // wrong service
		conn("172.28.0.51:40002", "172.28.0.20:443", 2*time.Second, "quic"), // other host
		conn("172.28.0.50:40003", "172.28.0.20:443", 3*time.Second, "QUIC"),
	}
	recs, err := FromConns(conns, spec())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records: %+v", len(recs), recs)
	}
	r := recs[1]
	if r.SessionID != 2 || r.Local.Port() != 40003 || r.Label != profile.LabelBenign || r.Profile != "chromium" ||
		!r.Start.Equal(t0.Add(3*time.Second)) || !r.End.Equal(t0.Add(5*time.Second)) {
		t.Errorf("record = %+v", r)
	}
	for _, rec := range recs {
		if err := rec.Validate(); err != nil {
			t.Errorf("invalid record: %v", err)
		}
	}

	allSvc := spec()
	allSvc.Services = nil
	if recs, _ := FromConns(conns, allSvc); len(recs) != 3 {
		t.Errorf("no service filter: %d records", len(recs))
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	bad := []func(*Spec){
		func(s *Spec) { s.Hosts = nil },
		func(s *Spec) { s.Hosts = []netip.Addr{{}} },
		func(s *Spec) { s.Label = "meh" },
		func(s *Spec) { s.Profile = "" },
		func(s *Spec) { s.RunID = "bad id" },
	}
	for i, mut := range bad {
		s := spec()
		mut(&s)
		if _, err := FromConns(nil, s); err == nil {
			t.Errorf("spec %d accepted", i)
		}
	}
}
