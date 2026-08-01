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

# VERSION is what the binary reports as `broker`. The default matches app/broker's compiled-in
# default, so an unstamped build and a `make build` agree: 0.0.0+dev orders below every real tag
# and is never mistaken for a release. The release workflow passes the tag with its leading "v"
# stripped — v1.2.0 becomes 1.2.0 — because the wire format's `broker` member has always been a
# bare semver and a consumer comparing versions should not have to strip a prefix.
#
# The commit is NOT passed here. The toolchain records vcs.revision, vcs.time and vcs.modified
# in the build info by itself, and `adb-broker version` reads them back from there. Stamping a
# second copy would create one that could disagree.
VERSION ?= 0.0.0+dev
LDFLAGS := -X $(MODULE)/app/broker.version=$(VERSION)

# The release build's platform and output path, used by build-release only. They are separate
# variables rather than GOOS/GOARCH so that setting one on the command line cannot silently
# cross-compile every other target in this file.
RELEASE_GOOS   ?= linux
RELEASE_GOARCH ?= $(shell go env GOARCH)
OUT            ?= $(BINARY)

.DEFAULT_GOAL := help

## help: list available targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'

## build: compile the binary into bin/. Override the reported version with VERSION=1.2.0
build:
	@mkdir -p $(BIN)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/adb-broker

## build-release: the exact configuration a published artifact is built in, for one platform.
## CGO_ENABLED=0 for a static, portable binary — which is also the configuration os/user
## behaves differently in, so it is the one test-nocgo covers. The release workflow calls this
## once per architecture rather than restating the build in YAML, so there is exactly one
## definition of how a shipped binary is built:
##
##   make build-release VERSION=1.2.0 RELEASE_GOARCH=arm64 OUT=dist/adb-broker-linux-arm64
##
## Linux only, deliberately: Windows does not compile, and macOS compiles but has no journald,
## so the anchor would silently never publish. See docs/phase3a_security_walkback.md.
build-release:
	@mkdir -p $(dir $(OUT))
	CGO_ENABLED=0 GOOS=$(RELEASE_GOOS) GOARCH=$(RELEASE_GOARCH) \
		go build -trimpath -ldflags "$(LDFLAGS)" -o $(OUT) ./cmd/adb-broker

## build-fixture: compile the fixture binary, which is absent from the release build
build-fixture:
	@mkdir -p $(BIN)
	go build -trimpath -tags=fixture -ldflags "$(LDFLAGS)" -o $(FIXTURE) ./cmd/adb-broker

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

## test-nocgo: unit tests in the configuration a release artifact is built in, CGO_ENABLED=0.
## Not a duplicate of test-unit: os/user behaves differently without cgo — user.Current answers
## an unresolvable uid out of $HOME there, which is why auditLogPath uses user.LookupId — so the
## configuration that ships has to be a configuration that is tested. -race is absent because
## the race detector requires cgo.
test-nocgo:
	CGO_ENABLED=0 go test -count=1 ./...

## test-device: tests requiring a phone attached. Skipped everywhere else; see docs.
test-device:
	go test -race -count=1 -tags=device -v ./...

## test: the full gate — unit tests in both build configurations, fixture build, lint,
## dependency and vuln checks
test: test-unit test-nocgo test-fixture lint deps-check vuln-check

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

.PHONY: help build build-release build-fixture vet fmt lint vuln-check deps-check \
	test-unit test-integration test-fixture test-nocgo test-device test cover \
	install clean
