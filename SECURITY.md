# Security policy

## Intended use

This repository is a **detection-training resource**. The beacon simulator reproduces the observable network behavior of QUIC command-and-control traffic so defenders can build and measure detections. It has no remote-control capability.

- It sends only benign, self-identifying payloads (`"sim": "quic-research/beaconsim"`).
- The lab server only acknowledges requests. Its protocol has no field for instructions.
- It refuses non-lab destinations (anything outside loopback, RFC 1918, RFC 6598 and IPv6 ULA) unless `-allow-public-targets` is passed.
- The Docker lab runs on an `internal` network with no route to the internet.

Run it only on networks you own or are authorized to test, and tell your SOC before you generate simulated C2 traffic on a monitored network.

## Reporting a vulnerability

Please report security issues privately through [GitHub's private vulnerability reporting](https://github.com/1337-llama/QUIC-Research-and-Defense/security/advisories/new) rather than in a public issue. Include the steps to reproduce and the impact you expect.

Issues in scope include, for example:

- a way to make the simulator reach a non-lab address without `-allow-public-targets`
- a way to make the simulator act on anything the server sends
- crashes or resource exhaustion in the log parsers on crafted input

## Supported versions

Only the latest release and the latest commit on `main` are supported.

## Verifying what you run

Release binaries, their checksums and the lab container image are signed with Sigstore by the release workflow and carry SLSA build provenance. The release notes give the commands to verify them. GitHub Actions in this repository are pinned to commit SHAs, and base images to digests. Supply-chain posture is tracked by [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/1337-llama/QUIC-Research-and-Defense).
