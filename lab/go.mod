module github.com/1337-llama/quic_research/lab

go 1.24

require (
	github.com/1337-llama/quic_research v0.0.0-00010101000000-000000000000
	github.com/quic-go/quic-go v0.59.1
)

// Minimum versions that fix vulnerabilities reported by govulncheck
// (GO-2026-5026, GO-2026-5970) in quic-go's dependencies.
require (
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/text v0.39.0 // indirect
)

// The lab module always builds against the core module in this repository.
replace github.com/1337-llama/quic_research => ../
