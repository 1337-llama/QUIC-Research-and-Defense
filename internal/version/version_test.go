package version

import (
	"runtime/debug"
	"testing"
)

// Not parallel: the tests swap package variables.
func TestString(t *testing.T) {
	origV, origRead := Version, readBuildInfo
	t.Cleanup(func() { Version, readBuildInfo = origV, origRead })

	info := func(v string, ok bool) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) { return &debug.BuildInfo{Main: debug.Module{Version: v}}, ok }
	}
	tests := []struct {
		linked string
		read   func() (*debug.BuildInfo, bool)
		want   string
	}{
		{"v1.2.3", info("v9.9.9", true), "v1.2.3"},
		{"", info("v0.4.0", true), "v0.4.0"},
		{"", info("(devel)", true), "dev"},
		{"", info("", true), "dev"},
		{"", info("v0.4.0", false), "dev"},
	}
	for _, tc := range tests {
		Version, readBuildInfo = tc.linked, tc.read
		if got := String(); got != tc.want {
			t.Errorf("String() with linked %q = %q, want %q", tc.linked, got, tc.want)
		}
	}
}
