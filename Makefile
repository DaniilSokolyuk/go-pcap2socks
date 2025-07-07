BINARY_NAME=go-pcap2socks
VERSION=$(shell git describe --tags --always --dirty)
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GOFLAGS=-ldflags="-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"
GO?=go

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

# Test
.PHONY: test
test:
	$(GO) test -v ./...

# Clean
.PHONY: clean
clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-*
	rm -f *.tar.gz *.zip *.sha256

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
	sha256sum $(BINARY_NAME)_$(VERSION)_linux_amd64.tar.gz > $(BINARY_NAME)_$(VERSION)_linux_amd64.tar.gz.sha256
	# Linux ARM64
	tar czf $(BINARY_NAME)_$(VERSION)_linux_arm64.tar.gz $(BINARY_NAME)-linux-arm64 README.md LICENSE install.md config.md
	sha256sum $(BINARY_NAME)_$(VERSION)_linux_arm64.tar.gz > $(BINARY_NAME)_$(VERSION)_linux_arm64.tar.gz.sha256
	# Darwin ARM64
	tar czf $(BINARY_NAME)_$(VERSION)_darwin_arm64.tar.gz $(BINARY_NAME)-darwin-arm64 README.md LICENSE install.md config.md
	sha256sum $(BINARY_NAME)_$(VERSION)_darwin_arm64.tar.gz > $(BINARY_NAME)_$(VERSION)_darwin_arm64.tar.gz.sha256
	# Windows AMD64
	zip $(BINARY_NAME)_$(VERSION)_windows_amd64.zip $(BINARY_NAME)-windows-amd64.exe README.md LICENSE install.md config.md
	sha256sum $(BINARY_NAME)_$(VERSION)_windows_amd64.zip > $(BINARY_NAME)_$(VERSION)_windows_amd64.zip.sha256

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build              - Build for current platform"
	@echo "  build-linux-amd64  - Build for Linux AMD64"
	@echo "  build-linux-arm64  - Build for Linux ARM64"
	@echo "  build-darwin-arm64 - Build for macOS ARM64"
	@echo "  build-windows-amd64- Build for Windows AMD64"
	@echo "  build-all          - Build for all platforms"
	@echo "  test               - Run tests"
	@echo "  clean              - Remove built binaries and packages"
	@echo "  install            - Install locally"
	@echo "  fmt                - Format code"
	@echo "  lint               - Run linters"
	@echo "  package            - Create release packages"
	@echo "  help               - Show this help"