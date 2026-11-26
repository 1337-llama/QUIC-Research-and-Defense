# Contributing

Thanks for helping defenders get better at detecting QUIC abuse. This guide covers how the code is organized, the quality bar, and how to make a change.

## Ground rules

This project exists to help defenders **detect** QUIC-based command and control. Contributions must keep it that way:

- **No capability.** The simulator sends benign, self-identifying payloads, and the lab server never returns instructions. Don't add command execution, file transfer, tasking, persistence, or anything else that would turn the simulator into a working implant. Tests enforce part of this, and reviewers enforce the rest.
- **Lab-only by default.** The simulator refuses non-lab destinations unless the operator passes `-allow-public-targets`. Keep the safe default.
- **No covert-channel implementations.** Simulator profiles shape observable behavior (timing, connection reuse, sizes, advertised transport settings). Don't hide data in protocol fields.

## Layout

| Path | What it is |
|---|---|
| `internal/` | Core module, standard library only. Profiles, scheduling, safety policy, payloads, ground truth, the beacon runner, the lab HTTP handler, CLI parsing, log parsers, reference detectors, scoring |
| `cmd/detscore/` | The detection scorer CLI |
| `lab/` | Separate module that depends on quic-go. The HTTP/3 transport and server, the `beaconsim` and `beaconsrv` binaries, the Dockerfile, and the Docker harness |
| `detections/` | Zeek scripts and Suricata rules |
| `docs/` | Research and guides |

The core module is kept **dependency-free** on purpose (CI enforces it). Everything that can be tested without a QUIC stack lives there, and the lab module is a thin adapter.

## Quality bar

Every change must pass `make check`. That runs:

- `gofmt` and `goimports` formatting
- `go vet` on both modules
- `golangci-lint` with the strict config in `.golangci.yml`
- core unit tests with the race detector
- a **90% coverage gate** on the core module
- the lab module's integration tests, which run real HTTP/3 over loopback

CI additionally runs fuzzing, `govulncheck`, CodeQL, validation of the Zeek and Suricata content, shellcheck, Markdown lint, and a full Docker lab run that gates on detection precision and recall.

Expectations for changes:

- **Tests come with the code.** New behavior needs unit tests; bug fixes need a test that fails without the fix.
- **Parsers get fuzz targets.** Anything that reads untrusted input (logs, profiles, payloads) needs one.
- **Golden files change deliberately.** If `detscore` output changes on purpose, run `make golden` and review the diff in your PR.
- **`//nolint` needs a reason.** The linter requires a specific linter name and an explanation.
- **Errors are wrapped with context** (`fmt.Errorf("doing x: %w", err)`) and checked with `errors.Is` / `errors.As`.

## Getting started

```sh
make help         # list targets
make check        # what CI runs, minus Docker
make fuzz         # fuzz every parser (FUZZTIME=30s by default)
make lab-run      # full Docker lab on a Linux host (~8 minutes)
```

The lab module needs its dependencies resolved once. If `lab/go.sum` is missing, run `make lab-tidy` and commit the result, or run the **Update lab dependencies** workflow from the Actions tab, which commits it for you.

## Pull requests

- Keep PRs focused, and describe what changed and why.
- Include the `detscore` report from `make lab-run` if you change a profile, a detector or the harness.
- CI must be green before review.

## Releasing

1. Move the `[Unreleased]` notes in `CHANGELOG.md` under a new version heading and merge that.
2. Run the **Tag a release** workflow on `main` with the version (for example `0.2.0`). It checks the changelog, tags `main` and runs the release. Pushing a signed tag yourself (`git tag -s v0.2.0 -m v0.2.0 && git push origin v0.2.0`) works too.
3. The release workflow builds, signs and attests everything, publishes the GitHub release and pushes the image to GHCR. CI's `Release config` job runs a GoReleaser snapshot on every pull request, so a broken release config fails there first.
