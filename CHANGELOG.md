# Changelog

Notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [semantic versioning](https://semver.org/). Until 1.0, minor versions may change command-line flags and file formats; such changes are called out here.

## [Unreleased]

### Fixed

- The results dashboard says "last run", not "last 1 runs".

## [0.1.0] - 2026-11-26

The first tagged release.

### Research and guides

- Ten chapters of documentation: how QUIC works, what a sensor can see, the threat landscape (Merlin, Salat Stealer, QUICAgent, KUKURAT), ranked detections, mitigations, the simulator, the detection lab, a Merlin lab guide, architecture and testing, and analyst exercises.

### Beacon simulator

- `beaconsim` and `beaconsrv` generate labeled QUIC C2-like traffic on quic-go, with no remote-control capability and lab-only destinations by default.
- Five profiles: `merlin-like`, `quicagent-like`, `low-and-slow`, `rotating-session` and `browser-like`.
- HTTPS fallback (`-fallback`): when QUIC can't be opened, the session is opened over HTTP/2 on TLS/TCP, as real implants do when UDP/443 is blocked. Ground truth records each session's transport.

### Detection lab

- Docker harness: isolated network, packet capture, Zeek 9 and Suricata 8 (with JA4), and precision/recall scoring against ground truth, gated in CI.
- Scenarios: persistent and per-beacon C2, HTTPS fallback, low-and-slow, rotating sessions, synthetic browsing and a real headless Chromium.
- `detscore` subcommands:
  - `detect`: reference detectors, with `-include-tls` to cover the HTTPS fallback.
  - `cadence`: beaconing inside a single connection, from packet timing.
  - `label`: ground truth for hosts that write none, such as a real browser.
  - `ja4`: fingerprints grouped by client.
  - `score`: precision and recall against ground truth.
  - `grade`: grades analyst exercises.
  - `trend`: the results dashboard.
  - `version`.
- Detection content: Zeek scripts, Suricata rules, Sigma rules, and Splunk/Elastic queries.

### Training

- Exercise mode (`make lab-exercise`) randomizes hosts, seeds and C2 names and holds the answer key back. `detscore grade` scores the analyst's host list.
- A nightly results dashboard on the `lab-results` branch.

### Engineering

- A stdlib-only core module with at least 90% test coverage (currently about 97%), fuzzing for every parser, golden files, loopback HTTP/3 and HTTP/2 integration tests, golangci-lint, CodeQL and govulncheck.
- Supply chain:
  - GitHub Actions pinned to commit SHAs, and base images pinned by digest.
  - OpenSSF Scorecard.
  - Releases include signed checksums (Sigstore), SBOMs and SLSA provenance for binaries and the multi-arch lab image on GHCR.

[Unreleased]: https://github.com/1337-llama/QUIC-Research-and-Defense/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/1337-llama/QUIC-Research-and-Defense/releases/tag/v0.1.0
