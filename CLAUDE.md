# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

go-pcap2socks functions like a router, allowing you to connect various devices such as an **XBOX**, **PlayStation (PS4, PS5)**, **Nintendo Switch**, mobile phones, printers and others to any SOCKS5 proxy server. Additionally, you can just start go-pcap2socks with the default direct outbound to share your VPN connection to any devices on your network.

## Build & Development Commands

### Building
```bash
# Build for current platform
make build

# Platform-specific builds
make build-linux-amd64
make build-linux-arm64
make build-darwin-arm64
make build-windows-amd64

# Build all platforms
make build-all
```

### Testing
```bash
# Run all tests
make test
# or
go test -v ./...

# Run specific test
go test -v ./transport -run TestName
```

### Code Quality
```bash
# Format code
make fmt
# or
go fmt ./...

# Run linters (requires golangci-lint)
make lint
```

### Running
```bash
# Edit/create config file
go-pcap2socks config

# Run (requires sudo/admin privileges)
sudo go-pcap2socks [config.json]
```

### Environment Variables
- `SLOG_LEVEL`: Set log level (debug, info, warn, error). Default: info

### Windows Builds
Windows builds use `CGO_ENABLED=0` (no CGO) while other platforms use `CGO_ENABLED=1` for pcap support.

## Architecture

### Core Components

**Network Stack (core/)**
- `stack.go`: Creates gVisor TCP/IP stack with IPv4/IPv6, TCP/UDP, ICMP, and ARP protocols
- `tcp.go`, `udpforwarder.go`: Handle TCP and UDP forwarding through the stack
- `nic.go`: Network Interface Card configuration
- `route.go`: Routing table setup
- The stack operates in promiscuous + spoofing mode to accept all traffic regardless of destination IP

**Device Layer (core/device/)**
- `pcap.go`: PCAP device implementation using gopacket/pcap for Layer 2 packet capture
- `device.go`: Device interface abstraction
- `iobased/endpoint.go`: I/O based endpoint for gVisor integration with MTU enforcement and ICMPSender interface
- Handles gratuitous ARP, MAC address learning, and BPF filtering
- Optional debug packet capture for troubleshooting

**Tunnel (tunnel/)**
- `tunnel.go`: Manages TCP/UDP connection queues and dispatches connections to handlers
- `tcp.go`: TCP connection handling with bidirectional streaming and half-close support
- `udp.go`: UDP session management with UPnP port mapping support
- `addr.go`: Address parsing utilities

**Proxy Layer (proxy/)**
- `proxy.go`: Base proxy interface
- `router.go`: Routes connections based on rules (IP ranges, ports)
- `direct.go`: Direct connection (no proxy)
- `socks5.go`: SOCKS5 proxy implementation
- `reject.go`: Reject connections
- `dns.go`: Local DNS resolver integration

**Configuration (cfg/)**
- `config.go`: JSON config parsing with support for:
  - PCAP settings (interface, IP, MAC, MTU, network)
  - Routing rules (src/dst IP/port based)
  - Multiple outbounds (direct, socks5, reject, dns)
  - Debug capture settings
  - Startup command execution

**Dialer (dialer/)**
- Platform-specific socket options for proper source IP binding
- Separate implementations for Linux, Darwin, FreeBSD, OpenBSD, Windows

**DNS (dns/)**
- `local.go`: Local DNS resolver
- `local_unix.go`, `local_windows.go`: Platform-specific DNS resolution

**ARP (arpr/)**
- `arp.go`: Gratuitous ARP implementation for network announcement

### Traffic Flow

1. **Packet Capture**: PCAP device captures Layer 2 Ethernet frames matching BPF filter
2. **MAC Learning**: Source IP/MAC pairs are learned and added to neighbor cache
3. **Stack Processing**: gVisor stack processes IP packets and dispatches to protocol handlers
4. **Connection Handling**:
   - TCP: Queued to `_tcpQueue`, handled by `handleTCPConn`
   - UDP: Handled by `HandleUDPConn` with NAT and UPnP support
5. **Routing**: Router matches rules based on src/dst IP/port and selects outbound
6. **Proxy**: Selected proxy (direct/socks5/reject/dns) establishes connection
7. **Bidirectional Copy**: Data is copied between client and remote connections

### Key Design Patterns

- **Adapter Pattern**: `core/adapter/` defines interfaces for TCP/UDP handlers
- **Strategy Pattern**: Multiple proxy implementations (direct, socks5, reject, dns)
- **Singleton-like Globals**: `_defaultProxy`, `_defaultDevice`, `_defaultStack` in main.go
- **Platform Abstraction**: Separate sockopt files for different OS-specific behavior
- **Buffer Pooling**: `common/pool/` for efficient memory management

### Configuration Model

Config supports:
- Multiple outbounds with tags (direct, socks5, reject, dns)
- Routing rules based on source/destination IP (CIDR) and ports (individual or ranges)
- Port ranges: "8000-9000"
- CIDR auto-completion: "192.168.1.1" becomes "192.168.1.1/32"

### Platform-Specific Considerations

- **Windows**: Uses CGO_ENABLED=0, special DNS resolution
- **Unix-like**: Uses CGO for pcap, platform-specific socket options
- **Darwin**: Special handling for interface gateway discovery
- Socket options vary per platform (IP_BOUND_IF, SO_BINDTODEVICE, etc.)