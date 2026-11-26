// Package version reports the version of the running binary.
package version

import "runtime/debug"

// Version is set at release time with
//
//	-ldflags "-X github.com/1337-llama/QUIC-Research-and-Defense/internal/version.Version=v1.2.3"
var Version = ""

// readBuildInfo is replaced in tests.
var readBuildInfo = debug.ReadBuildInfo

// String returns the release version if one was linked in, otherwise the
// module version recorded by "go install module@version", otherwise "dev".
func String() string {
	if Version != "" {
		return Version
	}
	if bi, ok := readBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}
