# quic_research

[![CI](https://github.com/1337-llama/quic_research/actions/workflows/ci.yml/badge.svg)](https://github.com/1337-llama/quic_research/actions/workflows/ci.yml)
[![Lab end-to-end](https://github.com/1337-llama/quic_research/actions/workflows/lab-e2e.yml/badge.svg)](https://github.com/1337-llama/quic_research/actions/workflows/lab-e2e.yml)
[![CodeQL](https://github.com/1337-llama/quic_research/actions/workflows/codeql.yml/badge.svg)](https://github.com/1337-llama/quic_research/actions/workflows/codeql.yml)

Research on the QUIC protocol and how defenders can detect its abuse in the wild, plus a **detection lab** that measures detections against labeled QUIC C2-like traffic.

## What's here

- **[Research docs](docs/README.md):** how QUIC works, what sensors can see, how attackers use it for C2, ranked detections and mitigations.
- **Beacon simulator** (`beaconsim`, `beaconsrv`): generates QUIC traffic shaped like real C2 families (Merlin, QUICAgent and others) and benign browsing, on quic-go, the Go QUIC stack real threats use. It sends only benign, self-identifying payloads, has no remote-control capability, and refuses non-lab destinations by default. → [docs](docs/06-beacon-simulator.md)
- **Detection lab:** a Docker harness that captures the traffic on an isolated network, runs Zeek and Suricata, and scores every detection for precision and recall against ground truth. → [docs](docs/07-detection-lab.md)
- **Detection content:** [Zeek scripts](detections/zeek/) and [Suricata rules](detections/suricata/), plus reference detectors in `detscore`.

## Quick start

```sh
make help        # list targets
make check       # format, vet, lint, race tests, coverage gate, lab integration tests
make lab-tidy    # first time only: resolve the lab module's dependencies
make lab-run     # full Docker lab on a Linux host (~8 minutes), prints a scored report
```

Score detections from your own sensors against a lab run:

```sh
go run ./cmd/detscore score -truth lab/harness/out/truth-merlin.jsonl \
  -notice my-zeek/notice.log -eve my-suricata/eve.json
```

## Layout

| Path | Contents |
|---|---|
| `docs/` | Research and guides |
| `internal/` | Core module (standard library only): profiles, scheduling, safety policy, beacon runner, lab HTTP handler, log parsers, detectors, scoring |
| `cmd/detscore/` | Runs reference detectors and scores detections against ground truth |
| `lab/` | quic-go transport and server, the `beaconsim`/`beaconsrv` binaries, Dockerfile and Docker harness |
| `detections/` | Zeek and Suricata content |

## Engineering

The core module has no dependencies, and CI enforces at least 90% test coverage on it. The test suite combines table-driven unit tests, deterministic simulation with a fake clock, statistical property tests, fuzzing for every parser, golden-file tests, real HTTP/3 integration tests on loopback, and a nightly end-to-end lab run gated on precision and recall. On top of that run golangci-lint (29 linters), CodeQL and govulncheck. See [Architecture and testing](docs/09-architecture-and-testing.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## Responsible use

This is a defensive training resource. Run the lab only on networks you own or are authorized to test. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
