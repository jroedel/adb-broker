# Tooling is pinned here rather than in go.mod `tool` directives so the module
# graph stays limited to what the binary actually imports — which, for this
# binary, is the standard library and nothing else. `go run pkg@version`
# downloads on demand and caches.
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@2025.1.1
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@latest

MODULE  := github.com/jroedel/adb-broker
BIN     := bin
BINARY  := $(BIN)/adb-broker
FIXTURE := $(BIN)/adb-broker-fixture

.DEFAULT_GOAL := help

## help: list available targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'

## build: compile the release binary into bin/
build:
	@mkdir -p $(BIN)
	go build -o $(BINARY) ./cmd/adb-broker

## build-fixture: compile the fixture binary, which is absent from the release build
build-fixture:
	@mkdir -p $(BIN)
	go build -tags=fixture -o $(FIXTURE) ./cmd/adb-broker

## vet: quick compile-level check, over both build configurations
vet:
	go vet ./...
	go vet -tags=fixture ./...

## fmt: format all Go source
fmt:
	go fmt ./...

## lint: go vet plus staticcheck, over both build configurations
lint: vet
	go run $(STATICCHECK) ./...
	go run $(STATICCHECK) -tags=fixture ./...

## vuln-check: scan for known vulnerabilities
vuln-check:
	go run $(GOVULNCHECK) ./...

## deps-check: assert the build graph is the standard library only
deps-check:
	@bad=$$(go list -deps ./... | grep -E '^[a-z0-9-]+(\.[a-z0-9-]+)+/' | grep -v '^$(MODULE)' || true); \
	if [ -n "$$bad" ]; then \
		echo "non-stdlib dependencies in the build graph:"; echo "$$bad"; exit 1; \
	fi; \
	echo "build graph is stdlib only"

## test-unit: unit tests only — no phone, no adb server, no root required
test-unit:
	go test -race -count=1 ./...

## test-integration: adds tests needing a running adb server with no device attached
test-integration:
	go test -race -count=1 -tags=integration ./...

## test-fixture: unit tests plus the fixture-mode build, which must stay compiling
test-fixture:
	go test -race -count=1 -tags=fixture ./...

## test-device: tests requiring a phone attached. Skipped everywhere else; see docs.
test-device:
	go test -race -count=1 -tags=device -v ./...

## test: the full gate — unit tests, fixture build, lint, dependency and vuln checks
test: test-unit test-fixture lint deps-check vuln-check

## cover: unit tests with a coverage summary
cover:
	go test -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

## install: copy the binary to ~/.local/bin. No root, no service account, no setuid.
## The broker creates its own audit log on first run; see ADB_BROKER.md, "Installation".
## Override the destination with PREFIX, e.g. PREFIX=/usr/local.
PREFIX ?= $(HOME)/.local

install: build
	install -D -m 0755 $(BINARY) $(PREFIX)/bin/adb-broker
	@echo "installed $(PREFIX)/bin/adb-broker"
	@echo "keep it at ONE path: anchors carry the publishing binary's _EXE, and a second copy"
	@echo "splits them into two identities that verify cannot see at once."

## clean: remove build and coverage artifacts
clean:
	rm -rf $(BIN) coverage.out

.PHONY: help build build-fixture vet fmt lint vuln-check deps-check \
	test-unit test-integration test-fixture test-device test cover \
	install clean
