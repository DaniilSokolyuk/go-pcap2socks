BINARY_NAME=go-pcap2socks
VERSION=$(shell git describe --tags --always --dirty)
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GOFLAGS=-ldflags="-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"
GO?=go

# Config file passed to the binary; override with `make run CONFIG=my.json`
CONFIG?=config.json
# Log level; override with `make run SLOG_LEVEL=debug`
SLOG_LEVEL?=info

# Default target
.PHONY: all
all: build

# Build for current platform
.PHONY: build
build:
	$(GO) build $(GOFLAGS) -o $(BINARY_NAME) .

# Platform-specific builds
.PHONY: build-linux-amd64
build-linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 $(GO) build $(GOFLAGS) -o $(BINARY_NAME)-linux-amd64 .

.PHONY: build-linux-arm64
build-linux-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc $(GO) build $(GOFLAGS) -o $(BINARY_NAME)-linux-arm64 .

.PHONY: build-darwin-arm64
build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 $(GO) build $(GOFLAGS) -o $(BINARY_NAME)-darwin-arm64 .

.PHONY: build-windows-amd64
build-windows-amd64:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(BINARY_NAME)-windows-amd64.exe .

# Build all platforms
.PHONY: build-all
build-all: build-linux-amd64 build-linux-arm64 build-darwin-arm64 build-windows-amd64

# Run locally. Packet capture needs root, hence sudo.
.PHONY: run
run: build
	sudo SLOG_LEVEL=$(SLOG_LEVEL) ./$(BINARY_NAME) $(CONFIG)

# Open the config file in an editor
.PHONY: config
config: build
	./$(BINARY_NAME) config

# Test (unit + component + end-to-end, no root and no pcap driver needed)
.PHONY: test
test:
	$(GO) test ./...

# Test with the race detector, which is what CI runs
.PHONY: test-race
test-race:
	$(GO) test -race -timeout 300s ./...

# End-to-end tests only: the whole engine driven over an in-memory ethernet segment
.PHONY: test-e2e
test-e2e:
	$(GO) test -v -timeout 300s ./e2e/

# Coverage report
.PHONY: cover
cover:
	$(GO) test -coverprofile=coverage.out -coverpkg=./... ./...
	$(GO) tool cover -func=coverage.out | tail -1

# Clean
.PHONY: clean
clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-*
	rm -f *.tar.gz *.zip
	rm -f coverage.out

# Install
.PHONY: install
install:
	$(GO) install $(GOFLAGS) .

# Format code
.PHONY: fmt
fmt:
	$(GO) fmt ./...

# Run linters
.PHONY: lint
lint:
	@which golangci-lint > /dev/null || echo "golangci-lint not installed"
	@which golangci-lint > /dev/null && golangci-lint run

# Package for release
.PHONY: package
package: clean build-all
	@echo "Creating release packages..."
	# Linux AMD64
	tar czf $(BINARY_NAME)_$(VERSION)_linux_amd64.tar.gz $(BINARY_NAME)-linux-amd64 README.md LICENSE install.md config.md
	# Linux ARM64
	tar czf $(BINARY_NAME)_$(VERSION)_linux_arm64.tar.gz $(BINARY_NAME)-linux-arm64 README.md LICENSE install.md config.md
	# Darwin ARM64
	tar czf $(BINARY_NAME)_$(VERSION)_darwin_arm64.tar.gz $(BINARY_NAME)-darwin-arm64 README.md LICENSE install.md config.md
	# Windows AMD64
	zip $(BINARY_NAME)_$(VERSION)_windows_amd64.zip $(BINARY_NAME)-windows-amd64.exe README.md LICENSE install.md config.md

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build              - Build for current platform"
	@echo "  build-linux-amd64  - Build for Linux AMD64"
	@echo "  build-linux-arm64  - Build for Linux ARM64"
	@echo "  build-darwin-arm64 - Build for macOS ARM64"
	@echo "  build-windows-amd64- Build for Windows AMD64"
	@echo "  build-all          - Build for all platforms"
	@echo "  run                - Build and run with sudo (CONFIG=, SLOG_LEVEL=)"
	@echo "  config             - Open the config file in an editor"
	@echo "  test               - Run all tests"
	@echo "  test-race          - Run all tests with the race detector"
	@echo "  test-e2e           - Run end-to-end tests only"
	@echo "  cover              - Run tests and print total coverage"
	@echo "  clean              - Remove built binaries and packages"
	@echo "  install            - Install locally"
	@echo "  fmt                - Format code"
	@echo "  lint               - Run linters"
	@echo "  package            - Create release packages"
	@echo "  help               - Show this help"