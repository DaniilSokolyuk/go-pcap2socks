# Installation

go-pcap2socks depends on libpcap and is fully compatible with any version on any platform.

## Prerequisites

- Go 1.21 or later ([download](https://go.dev/dl/))
- libpcap (see platform-specific instructions below)

## Installing from Source

To build the latest stable version:

```bash
go install github.com/DaniilSokolyuk/go-pcap2socks@latest
```

To build the latest development version:

```bash
go install github.com/DaniilSokolyuk/go-pcap2socks@main
```

## Dependencies

### Linux

```bash
# Debian/Ubuntu
sudo apt install libpcap-dev

# Fedora/RHEL
sudo dnf install libpcap-devel

# Arch
sudo pacman -S libpcap

# Alpine
sudo apk add libpcap-dev
```

### macOS

```bash
brew install libpcap
```

### Windows

Download and install [Npcap](https://npcap.com/#download) with "WinPcap API-compatible Mode" enabled.

## Running

```bash
# Open configuration in editor
go-pcap2socks config

# Run with default config (requires root)
sudo go-pcap2socks

# Run with custom config
sudo go-pcap2socks /path/to/config.json
```

## Termux (Android)

**Note:** Requires a rooted Android device as packet capture needs root privileges.

```bash
# Install dependencies
pkg update
pkg install root-repo
pkg install golang libpcap tsu

# Install go-pcap2socks
go install github.com/DaniilSokolyuk/go-pcap2socks@latest

# Run with root (requires rooted device)
sudo $HOME/go/bin/go-pcap2socks

# Or use tsu for better root handling
tsu -c "$HOME/go/bin/go-pcap2socks"
```