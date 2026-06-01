BINARY      := pipelinesentinel
MODULE      := github.com/mdryaaan/pipelinesentinel
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE)/pkg/version.Version=$(VERSION) \
	-X $(MODULE)/pkg/version.Commit=$(COMMIT) \
	-X $(MODULE)/pkg/version.BuildDate=$(BUILD_DATE)

GO      ?= go
GOFLAGS ?=

.DEFAULT_GOAL := help

## help: list the available targets
.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | awk -F': ' '{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

## build: compile the binary into ./bin
.PHONY: build
build:
	@mkdir -p bin
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/$(BINARY) .
	@echo "built bin/$(BINARY) $(VERSION)"

## install: install the binary into GOPATH/bin
.PHONY: install
install:
	$(GO) install $(GOFLAGS) -ldflags '$(LDFLAGS)' .

## test: run the test suite with coverage
.PHONY: test
test:
	$(GO) test ./... -race -coverprofile=coverage.out -covermode=atomic
	@$(GO) tool cover -func=coverage.out | tail -1

## cover: open the HTML coverage report
.PHONY: cover
cover: test
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "wrote coverage.html"

## lint: run go vet and golangci-lint when it is installed
.PHONY: lint
lint:
	$(GO) vet ./...
	@command -v golangci-lint >/dev/null 2>&1 \
		&& golangci-lint run ./... \
		|| echo "golangci-lint not installed; ran go vet only"

## fmt: format the tree and tidy the module
.PHONY: fmt
fmt:
	$(GO) fmt ./...
	$(GO) mod tidy

## demo: audit the bundled workflows without touching the network
.PHONY: demo
demo: build
	-./bin/$(BINARY) audit --offline

## eval: score the detector against the labelled corpus
.PHONY: eval
eval: build
	./bin/$(BINARY) eval

## eval-md: write the evaluation section used in the README
.PHONY: eval-md
eval-md: build
	./bin/$(BINARY) eval --format markdown -o eval.md
	@echo "wrote eval.md"

## report: write a markdown report and its JSON companion
.PHONY: report
report: build
	-./bin/$(BINARY) report --offline -o report.md --json audit-results.json
	@echo "wrote report.md and audit-results.json"

## clean: remove build output and generated reports
.PHONY: clean
clean:
	rm -rf bin coverage.out coverage.html
	rm -f report.md eval.md eval.json audit-results.json explained-results.json prcomment.md digest.md

## ci: everything the pipeline runs
.PHONY: ci
ci: fmt lint test eval
