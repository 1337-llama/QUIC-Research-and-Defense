package eve

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

const sample = `{"timestamp":"2026-11-23T12:00:05.250000+0000","flow_id":1,"event_type":"alert","src_ip":"172.28.0.30","src_port":50001,"dest_ip":"172.28.0.10","dest_port":443,"proto":"UDP","app_proto":"quic","alert":{"action":"allowed","gid":1,"signature_id":9000002,"rev":1,"signature":"QUIC uncommon version","category":"","severity":3}}
{"timestamp":"2026-11-23T12:00:06.000000+0000","event_type":"quic","src_ip":"172.28.0.30","src_port":50001,"dest_ip":"172.28.0.10","dest_port":443,"proto":"UDP","quic":{"version":"1"}}

{"timestamp":"2026-11-23T13:00:07.5+01:00","event_type":"alert","src_ip":"fd00::2","src_port":40000,"dest_ip":"::ffff:10.0.0.1","dest_port":443,"proto":"udp","alert":{"signature_id":2,"signature":"Other"}}
`

func TestReadAlerts(t *testing.T) {
	t.Parallel()
	as, err := ReadAlerts(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 2 {
		t.Fatalf("got %d alerts, want 2 (non-alert events skipped)", len(as))
	}
	a := as[0]
	want := Alert{
		TS:  time.Date(2026, 11, 23, 12, 0, 5, 25e7, time.UTC),
		Src: netip.MustParseAddrPort("172.28.0.30:50001"), Dst: netip.MustParseAddrPort("172.28.0.10:443"),
		Proto: "UDP", AppProto: "quic", Signature: "QUIC uncommon version", SignatureID: 9000002,
	}
	if a != want {
		t.Errorf("alert 0:\n got %+v\nwant %+v", a, want)
	}
	b := as[1]
	if !b.TS.Equal(time.Date(2026, 11, 23, 12, 0, 7, 5e8, time.UTC)) || b.Proto != "UDP" {
		t.Errorf("alert 1 = %+v", b)
	}
	if b.Dst != netip.MustParseAddrPort("10.0.0.1:443") {
		t.Errorf("IPv4-mapped address not unmapped: %v", b.Dst)
	}
}

func TestReadAlertsErrors(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"bad json":     `{"event_type":`,
		"no signature": `{"timestamp":"2026-11-23T12:00:00.000000+0000","event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2"}`,
		"bad time":     `{"timestamp":"noon","event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","alert":{"signature":"s"}}`,
		"bad src":      `{"timestamp":"2026-11-23T12:00:00.000000+0000","event_type":"alert","src_ip":"x","dest_ip":"10.0.0.2","alert":{"signature":"s"}}`,
		"bad dst":      `{"timestamp":"2026-11-23T12:00:00.000000+0000","event_type":"alert","src_ip":"10.0.0.1","dest_ip":"x","alert":{"signature":"s"}}`,
		"bad port":     `{"timestamp":"2026-11-23T12:00:00.000000+0000","event_type":"alert","src_ip":"10.0.0.1","src_port":70000,"dest_ip":"10.0.0.2","alert":{"signature":"s"}}`,
	}
	for name, in := range tests {
		_, err := ReadAlerts(strings.NewReader(in))
		if err == nil || !strings.Contains(err.Error(), "line 1") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := ReadAlerts(strings.NewReader(strings.Repeat("x", MaxLineBytes+1))); err == nil {
		t.Error("oversized line accepted")
	}
}

func FuzzReadAlerts(f *testing.F) {
	f.Add([]byte(sample))
	f.Fuzz(func(t *testing.T, data []byte) {
		as, err := ReadAlerts(strings.NewReader(string(data)))
		if err != nil {
			return
		}
		for _, a := range as {
			if a.Signature == "" || !a.Src.IsValid() || !a.Dst.IsValid() || a.TS.IsZero() {
				t.Fatalf("accepted incomplete alert %+v", a)
			}
		}
	})
}
