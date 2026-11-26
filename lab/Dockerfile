# syntax=docker/dockerfile:1
#
# Lab image: beaconsrv, beaconsim and detscore as static binaries on a
# distroless, non-root base. Build from the repository root:
#
#   docker build -f lab/Dockerfile -t quic-research-lab:local .
#
# Base images are pinned by digest; Dependabot keeps the digests current.
# The build stage runs on the build platform and cross-compiles, so
# multi-platform builds don't need emulation.

FROM --platform=$BUILDPLATFORM golang:1.26-bookworm@sha256:ea47ee45f1284d60f9cc09cb2c3bb4f508c256b640bd8bb30342ff13d1adcb52 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath

# Download dependencies in their own layer for caching.
COPY go.mod ./
COPY lab/go.mod lab/go.sum ./lab/
RUN cd lab && go mod download && go mod verify

COPY . .
RUN ldflags="-s -w -X github.com/1337-llama/QUIC-Research-and-Defense/internal/version.Version=${VERSION}" \
 && cd lab && GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="$ldflags" -o /out/ ./cmd/beaconsim ./cmd/beaconsrv \
 && cd /src && GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="$ldflags" -o /out/ ./cmd/detscore

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL org.opencontainers.image.source="https://github.com/1337-llama/QUIC-Research-and-Defense" \
      org.opencontainers.image.description="QUIC detection lab: beacon simulator, lab server and detscore" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/ /usr/local/bin/
USER nonroot:nonroot
