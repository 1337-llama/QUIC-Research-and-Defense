# syntax=docker/dockerfile:1
#
# Lab image: beaconsrv, beaconsim and detscore as static binaries on a
# distroless, non-root base. Build from the repository root:
#
#   docker build -f lab/Dockerfile -t quic-research-lab:local .

FROM golang:1.26-bookworm AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath

# Download dependencies in their own layer for caching.
COPY go.mod ./
COPY lab/go.mod lab/go.sum ./lab/
RUN cd lab && go mod download && go mod verify

COPY . .
RUN cd lab && go build -ldflags="-s -w" -o /out/ ./cmd/beaconsim ./cmd/beaconsrv \
 && cd /src && go build -ldflags="-s -w" -o /out/ ./cmd/detscore

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /usr/local/bin/
USER nonroot:nonroot
