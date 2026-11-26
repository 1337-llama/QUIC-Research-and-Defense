# Developer entry points. `make help` lists targets.
#
# The repository has two Go modules:
#   .      core: dependency-free simulator logic, parsers, detectors, scorer
#   lab/   QUIC transport (quic-go), the lab binaries and the Docker harness

GO        ?= go
LINT      ?= golangci-lint
COVER_MIN ?= 90
FUZZTIME  ?= 30s

# package:FuzzTarget pairs run by `make fuzz`.
FUZZ_TARGETS := \
	./internal/profile:FuzzLoad \
	./internal/payload:FuzzDecodeBeacon \
	./internal/zeeklog:FuzzRead \
	./internal/eve:FuzzReadAlerts \
	./internal/pcap:FuzzReader

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: check
check: fmt-check vet lint test-race cover lab-test ## Everything CI runs, except the Docker lab

.PHONY: fmt
fmt: ## Format all Go code
	$(LINT) fmt ./...
	cd lab && $(LINT) fmt --config ../.golangci.yml ./...

.PHONY: fmt-check
fmt-check: ## Fail if any Go file is not gofmt-clean
	@out="$$(gofmt -l . )"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet: ## go vet both modules
	$(GO) vet ./...
	cd lab && $(GO) vet ./...

.PHONY: lint
lint: ## golangci-lint both modules
	$(LINT) run ./...
	cd lab && $(LINT) run --config ../.golangci.yml ./...

.PHONY: test
test: ## Core unit tests
	$(GO) test ./...

.PHONY: test-race
test-race: ## Core unit tests with the race detector
	$(GO) test -race -count=1 ./...

.PHONY: cover
cover: ## Core tests with a coverage gate (COVER_MIN, default 90%)
	$(GO) test -count=1 -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...
	scripts/coverage-gate.sh coverage.out $(COVER_MIN)

.PHONY: fuzz
fuzz: ## Run every fuzz target for FUZZTIME (default 30s)
	@set -e; for t in $(FUZZ_TARGETS); do \
		pkg="$${t%%:*}"; fn="$${t##*:}"; \
		echo "==> $$fn ($$pkg)"; \
		$(GO) test -run='^$$' -fuzz="^$$fn\$$" -fuzztime=$(FUZZTIME) "$$pkg"; \
	done

.PHONY: golden
golden: ## Regenerate detscore golden files after an intended output change
	$(GO) test ./cmd/detscore -run Golden -update

.PHONY: vuln
vuln: ## govulncheck both modules
	govulncheck ./...
	cd lab && govulncheck ./...

.PHONY: lab-tidy
lab-tidy: ## Resolve lab module dependencies and write lab/go.sum
	cd lab && $(GO) mod tidy

.PHONY: lab-test
lab-test: ## Lab module unit and integration tests (real HTTP/3 on loopback)
	cd lab && $(GO) test -race -count=1 ./...

.PHONY: lab-image
lab-image: ## Build the lab Docker image
	docker build -f lab/Dockerfile -t quic-research-lab:local .

.PHONY: lab-run
lab-run: ## Run the full Docker detection lab (Linux host, ~8 minutes)
	lab/harness/run.sh

.PHONY: clean
clean: ## Remove build and lab outputs
	rm -rf coverage.out lab/harness/out
