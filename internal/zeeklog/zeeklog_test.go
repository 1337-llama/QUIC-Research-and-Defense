package zeeklog

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func open(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestReadTSV(t *testing.T) {
	t.Parallel()
	recs, err := Read(open(t, "conn.tsv.log"))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 4 {
		t.Fatalf("got %d records", len(recs))
	}
	if recs[0]["service"] != "quic,ssl" || recs[0]["id.resp_p"] != "443" {
		t.Errorf("record 0 = %v", recs[0])
	}
	if _, ok := recs[3]["service"]; ok {
		t.Errorf("unset field should be absent: %v", recs[3])
	}
}

func TestConnTSVAndJSONAgree(t *testing.T) {
	t.Parallel()
	tsv, err := ReadConns(open(t, "conn.tsv.log"))
	if err != nil {
		t.Fatal(err)
	}
	js, err := ReadConns(open(t, "conn.json.log"))
	if err != nil {
		t.Fatal(err)
	}
	if len(js) != 2 {
		t.Fatalf("json: %d conns", len(js))
	}
	for i := range js {
		a, b := tsv[i], js[i]
		if a.UID != b.UID || !a.TS.Equal(b.TS) || a.Endpoints != b.Endpoints || a.Duration != b.Duration ||
			a.OrigBytes != b.OrigBytes || a.RespBytes != b.RespBytes || strings.Join(a.Service, ",") != strings.Join(b.Service, ",") {
			t.Errorf("conn %d differs:\n tsv  %+v\n json %+v", i, a, b)
		}
	}
	c := tsv[0]
	if c.Orig != netip.MustParseAddrPort("172.28.0.30:50001") || c.Resp != netip.MustParseAddrPort("172.28.0.10:443") {
		t.Errorf("endpoints = %+v", c.Endpoints)
	}
	if c.Duration != 360*time.Second+250*time.Millisecond || !c.HasService("QUIC") || c.HasService("dns") {
		t.Errorf("conn = %+v", c)
	}
	if tsv[1].TS.Nanosecond() != 123456000 {
		t.Errorf("fractional ts = %v", tsv[1].TS)
	}
	if tsv[3].Duration != 0 || tsv[3].Service != nil {
		t.Errorf("unset fields not zero: %+v", tsv[3])
	}
}

func TestReadQUIC(t *testing.T) {
	t.Parallel()
	qs, err := ReadQUIC(open(t, "quic.tsv.log"))
	if err != nil {
		t.Fatal(err)
	}
	if len(qs) != 2 {
		t.Fatalf("got %d", len(qs))
	}
	if qs[0].ServerName != "c2" || qs[0].ClientProtocol != "h3" || qs[0].History != "ISisIH" || qs[0].Version != "1" {
		t.Errorf("quic 0 = %+v", qs[0])
	}
	if qs[1].ServerName != "" {
		t.Errorf("(empty) should parse as empty string, got %q", qs[1].ServerName)
	}
}

func TestReadNotices(t *testing.T) {
	t.Parallel()
	ns, err := ReadNotices(open(t, "notice.tsv.log"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != 2 || ns[0].Note != "QUICHunt::Long_QUIC_Connection" || ns[0].Orig.Port() != 50001 {
		t.Fatalf("notices = %+v", ns)
	}
	if ns[1].Orig.IsValid() {
		t.Errorf("notice without endpoints should have zero endpoints: %+v", ns[1])
	}
}

func TestSortedByTime(t *testing.T) {
	t.Parallel()
	in := `{"ts":20,"uid":"b","id.orig_h":"10.0.0.1","id.orig_p":1,"id.resp_h":"10.0.0.2","id.resp_p":443}
{"ts":10,"uid":"a","id.orig_h":"10.0.0.1","id.orig_p":1,"id.resp_h":"10.0.0.2","id.resp_p":443}`
	cs, err := ReadConns(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if cs[0].UID != "a" {
		t.Errorf("not sorted: %+v", cs)
	}
}

func TestEmptyInput(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"", "\n\n  \n"} {
		recs, err := Read(strings.NewReader(in))
		if err != nil || len(recs) != 0 {
			t.Errorf("Read(%q) = %v, %v", in, recs, err)
		}
	}
}

func TestCustomSeparators(t *testing.T) {
	t.Parallel()
	in := "#separator |\n#set_separator|;\n#empty_field|E\n#unset_field|U\n#fields|a|b|c|d\nx|U|E|p;q\n"
	recs, err := Read(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	r := recs[0]
	if r["a"] != "x" || r["c"] != "" || r["d"] != "p,q" {
		t.Errorf("record = %v", r)
	}
	if _, ok := r["b"]; ok {
		t.Errorf("unset field present: %v", r)
	}
}

func TestReadErrors(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"data before fields": "1\t2\n",
		"field count":        "#fields\ta\tb\n1\n",
		"bad separator":      "#separator \\xZZ\n",
		"empty separator":    "#separator \n",
		"bad json":           "{\"a\":\n",
	}
	for name, in := range tests {
		if _, err := Read(strings.NewReader(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := Read(strings.NewReader("#fields\ta\n" + strings.Repeat("x", MaxLineBytes+1))); err == nil {
		t.Error("oversized line accepted")
	}
}

func TestTypedParseErrors(t *testing.T) {
	t.Parallel()
	good := Record{"ts": "1", "uid": "u", "id.orig_h": "10.0.0.1", "id.orig_p": "1", "id.resp_h": "10.0.0.2", "id.resp_p": "443"}
	with := func(k, v string) Record {
		r := Record{}
		for kk, vv := range good {
			r[kk] = vv
		}
		if v == "" {
			delete(r, k)
		} else {
			r[k] = v
		}
		return r
	}
	bad := map[string]Record{
		"no ts":      with("ts", ""),
		"bad ts":     with("ts", "yesterday"),
		"bad addr":   with("id.orig_h", "999.1.1.1"),
		"bad port":   with("id.resp_p", "99999"),
		"bad dur":    with("duration", "-5"),
		"bad bytes":  with("orig_bytes", "many"),
		"bad rbytes": with("resp_bytes", "1.5"),
	}
	for name, r := range bad {
		if _, err := ParseConn(r); err == nil {
			t.Errorf("ParseConn %s: expected error", name)
		}
	}
	if _, err := ParseQUIC(with("ts", "x")); err == nil {
		t.Error("ParseQUIC bad ts accepted")
	}
	if _, err := ParseQUIC(with("id.resp_h", "x")); err == nil {
		t.Error("ParseQUIC bad addr accepted")
	}
	if _, err := ParseNotice(Record{"ts": "1"}); err == nil {
		t.Error("notice without note accepted")
	}
	if _, err := ParseNotice(Record{"ts": "x", "note": "n"}); err == nil {
		t.Error("notice with bad ts accepted")
	}
	if _, err := ParseNotice(Record{"ts": "1", "note": "n", "id.orig_h": "bad"}); err == nil {
		t.Error("notice with bad endpoints accepted")
	}
	if _, err := ReadConns(strings.NewReader(`{"ts":"x"}`)); err == nil || !strings.Contains(err.Error(), "record 1") {
		t.Errorf("ReadConns error should name the record: %v", err)
	}
}

func TestTime(t *testing.T) {
	t.Parallel()
	got, err := Time("1795435200.5")
	if err != nil || !got.Equal(time.Unix(1795435200, 5e8)) || got.Location() != time.UTC {
		t.Errorf("Time = %v, %v", got, err)
	}
	got, err = Time("2026-11-23T12:00:00.25+01:00")
	if err != nil || !got.Equal(time.Date(2026, 11, 23, 11, 0, 0, 25e7, time.UTC)) {
		t.Errorf("Time(ISO) = %v, %v", got, err)
	}
	for _, bad := range []string{"", "NaN", "Inf", "noon"} {
		if _, err := Time(bad); err == nil {
			t.Errorf("Time(%q) accepted", bad)
		}
	}
	if _, err := Interval("NaN"); err == nil {
		t.Error("Interval(NaN) accepted")
	}
}

func FuzzRead(f *testing.F) {
	for _, name := range []string{"conn.tsv.log", "conn.json.log", "quic.tsv.log", "notice.tsv.log"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		recs, err := Read(strings.NewReader(string(data)))
		if err != nil {
			return
		}
		// Typed parsers must never panic on anything Read accepts.
		for _, r := range recs {
			_, _ = ParseConn(r)
			_, _ = ParseQUIC(r)
			_, _ = ParseNotice(r)
		}
	})
}
