module github.com/1337-llama/quic_research/lab

go 1.24

require (
	github.com/1337-llama/quic_research v0.0.0-00010101000000-000000000000
	github.com/quic-go/quic-go v0.48.2
)

// The lab module always builds against the core module in this repository.
replace github.com/1337-llama/quic_research => ../
