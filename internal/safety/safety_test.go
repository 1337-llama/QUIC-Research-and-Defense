package safety

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestCheckAddr(t *testing.T) {
	t.Parallel()
	tests := []struct {
		addr       string
		lab, pubOK bool // allowed by default; allowed with AllowPublic
	}{
		{"127.0.0.1", true, true},
		{"::1", true, true},
		{"10.1.2.3", true, true},
		{"172.16.0.1", true, true},
		{"172.31.255.254", true, true},
		{"192.168.1.1", true, true},
		{"100.64.0.1", true, true},
		{"100.127.255.254", true, true},
		{"fd00::1", true, true},
		{"::ffff:10.0.0.1", true, true},
		{"172.32.0.1", false, true},
		{"100.128.0.1", false, true},
		{"8.8.8.8", false, true},
		{"2001:4860:4860::8888", false, true},
		{"0.0.0.0", false, false},
		{"::", false, false},
		{"224.0.0.1", false, false},
		{"ff02::1", false, false},
		{"255.255.255.255", false, false},
	}
	for _, tc := range tests {
		a := netip.MustParseAddr(tc.addr)
		if err := (Policy{}).CheckAddr(a); (err == nil) != tc.lab {
			t.Errorf("default CheckAddr(%s) err = %v, want allowed=%v", tc.addr, err, tc.lab)
		}
		if err := (Policy{AllowPublic: true}).CheckAddr(a); (err == nil) != tc.pubOK {
			t.Errorf("AllowPublic CheckAddr(%s) err = %v, want allowed=%v", tc.addr, err, tc.pubOK)
		}
	}
	if err := (Policy{}).CheckAddr(netip.Addr{}); err == nil {
		t.Error("zero Addr accepted")
	}
}

func TestPublicRejectionWrapsErrNotLab(t *testing.T) {
	t.Parallel()
	err := (Policy{}).CheckAddr(netip.MustParseAddr("1.1.1.1"))
	if !errors.Is(err, ErrNotLab) {
		t.Fatalf("err = %v, want ErrNotLab", err)
	}
	if !strings.Contains(err.Error(), "--allow-public-targets") {
		t.Errorf("error should explain the opt-in: %v", err)
	}
}

func TestResolve(t *testing.T) {
	t.Parallel()
	r := fakeResolver{
		"c2":      addrs("172.28.0.10"),
		"dual":    addrs("10.0.0.1", "fd00::1"),
		"mixed":   addrs("10.0.0.1", "8.8.8.8"),
		"public":  addrs("8.8.8.8"),
		"nothing": {},
	}
	ctx := context.Background()

	got, err := (Policy{}).Resolve(ctx, r, "c2:443")
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddrPort("172.28.0.10:443") {
		t.Fatalf("Resolve(c2:443) = %v, %v", got, err)
	}
	got, err = (Policy{}).Resolve(ctx, r, "dual:8443")
	if err != nil || len(got) != 2 {
		t.Fatalf("Resolve(dual) = %v, %v", got, err)
	}
	got, err = (Policy{}).Resolve(ctx, nil, "[::1]:443")
	if err != nil || got[0] != netip.MustParseAddrPort("[::1]:443") {
		t.Fatalf("Resolve(IP literal) = %v, %v", got, err)
	}
	if _, err := (Policy{AllowPublic: true}).Resolve(ctx, r, "public:443"); err != nil {
		t.Fatalf("AllowPublic Resolve(public) = %v", err)
	}

	failures := map[string]string{
		"mixed:443":    "not a lab address",
		"public:443":   "not a lab address",
		"8.8.8.8:443":  "not a lab address",
		"nothing:443":  "no addresses",
		"unknown:443":  "no such host",
		"c2":           "missing port",
		"c2:0":         "invalid port",
		"c2:99999":     "invalid port",
		"c2:https":     "invalid port",
		"0.0.0.0:443":  "not a unicast",
		"name-no-r:44": "no resolver",
	}
	for target, want := range failures {
		var res Resolver = r
		if strings.HasPrefix(target, "name-no-r") {
			res = nil
		}
		_, err := (Policy{}).Resolve(ctx, res, target)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Resolve(%q) err = %v, want containing %q", target, err, want)
		}
	}
}
