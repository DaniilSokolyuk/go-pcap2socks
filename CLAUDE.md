# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

go-pcap2socks is a PCAP-based proxy that redirects network traffic from any device (XBOX, PlayStation, Nintendo Switch, mobile phones, etc.) to a SOCKS5 proxy server. It operates at Layer 2 using packet capture and a gVisor TCP/IP stack to intercept and route traffic.

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
- `pmtud.go`: Path MTU Discovery implementation (sends ICMP Type 3 Code 4 messages)
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

### MTU Discovery

The application includes automatic MTU discovery to help devices correctly determine the maximum transmission unit:

**gVisor Automatic MSS Calculation**:
- gVisor TCP/IP stack automatically calculates advertised MSS based on endpoint MTU
- MSS = MTU - 40 (IP header 20 + TCP header 20)
- Configured via `netConfig.MTU` passed to `iobased.New()`
- No manual MSS clamping needed - gVisor handles it correctly
- See `gvisor/pkg/tcpip/transport/tcp/endpoint.go:calculateAdvertisedMSS()`

**Path MTU Discovery (PMTUD) via ICMP (core/device/pmtud.go)**:
- `ICMPSender` interface defined in `iobased/endpoint.go` for sending ICMP messages
- `pcapICMPSender` struct in `pmtud.go` implements the interface for PCAP-based sending
- Sends ICMP Type 3 Code 4 (Fragmentation Needed) when packets exceed MTU
- Constructs complete Ethernet frames with ICMP payload at Layer 2
- ICMP payload includes original IP header + 8 bytes of data per RFC 792
- MTU value encoded in ICMP Seq field (Id field unused per RFC)
- Requires MAC address lookup from learned IP-MAC table
- Handles dynamic MTU discovery for networks with varying MTU

**Implementation Details**:
- MTU configured in `cfg.PCAP.MTU` (config.json) or defaults to interface MTU
- Stored in `PCAP.mtu` field (may differ from `Interface.MTU`)
- Passed to gVisor stack via `iobased.New(rw, netConfig.MTU, offset, localMAC)`
- `iobased.Endpoint` defines `ICMPSender` interface and detects oversized packets in `dispatchLoop()`
- `pcapICMPSender` (core/device/pmtud.go) constructs Ethernet+IP+ICMP frames
- Uses `gopacket` to serialize layers with automatic checksum calculation
- Loop prevention: filters out self-generated ICMP packets in promiscuous mode
- Debug logging shows MTU-related events when `SLOG_LEVEL=debug`

**Logging**:
- `[MTU]` prefix for MTU discovery events
- `[ICMP]` prefix for ICMP message operations