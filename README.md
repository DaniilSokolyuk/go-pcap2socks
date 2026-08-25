# go-pcap2socks

go-pcap2socks is a proxy that redirects traffic from any device to a SOCKS5 proxy.

go-pcap2socks functions like a router, allowing you to connect various devices such as an **XBOX**, **PlayStation (PS4, PS5)**, **Nintendo Switch**, mobile phones, printers and others to any SOCKS5 proxy server. Additionally, you can just start go-pcap2socks with the default direct outbound to share your VPN connection to any devices on your network.

- [Quick Start](#quick-start)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Installing from Source](#installing-from-source)
  - [Dependencies](#dependencies)
  - [Running](#running)
  - [Termux (Android)](#termux-android)
- [Configuration](#configuration)
  - [How it works](#how-it-works)
  - [CLI Commands](#cli-commands)
  - [executeOnStart](#executeonstart)
  - [pcap](#pcap)
  - [dns](#dns)
  - [routing](#routing)
  - [outbounds](#outbounds)
  - [capture](#capture)
  - [Complete Example Configurations](#complete-example-configurations)
- [Troubleshooting](#troubleshooting)
- [Credits](#credits)

## Quick Start

```bash
# Install
go install github.com/DaniilSokolyuk/go-pcap2socks@latest

# Configure
go-pcap2socks config

# Run
sudo go-pcap2socks
```

## Installation

go-pcap2socks depends on libpcap and is fully compatible with any version on any platform.

### Prerequisites

- Go 1.26 or later ([download](https://go.dev/dl/))
- libpcap (see platform-specific instructions below)

### Installing from Source

To build the latest stable version:

```bash
go install github.com/DaniilSokolyuk/go-pcap2socks@latest
```

To build the latest development version:

```bash
go install github.com/DaniilSokolyuk/go-pcap2socks@main
```

### Dependencies

#### Linux

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

#### macOS

```bash
brew install libpcap
```

#### Windows

Download and install [Npcap](https://npcap.com/#download) with "WinPcap API-compatible Mode" enabled.

### Running

```bash
# Open configuration in editor
go-pcap2socks config

# Run with default config (requires root)
sudo go-pcap2socks

# Run with custom config
sudo go-pcap2socks /path/to/config.json
```

### Termux (Android)

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

## Configuration

The configuration uses JSON format. The config file is taken from the first command line argument; without one, go-pcap2socks uses `config.json` next to the executable and creates it with default settings on first run.

The whole config is validated at startup: unknown field names (typos), invalid values, duplicate outbound tags, rules referencing unknown outbounds or a missing default outbound all stop the program with an error instead of silently misbehaving.

### How it works

go-pcap2socks announces itself on your LAN as the gateway of the virtual network configured in `pcap`. On start it prints the settings to enter on the device: the usable IP range, subnet mask, gateway address and MTU. Give the device a static IP from that range with the printed gateway, and its internet-bound traffic arrives at go-pcap2socks, where every TCP connection and UDP session is matched against the routing rules and forwarded through the selected outbound.

### CLI Commands

#### Opening Configuration in Editor

To open the configuration file in your default text editor:

```bash
go-pcap2socks config
```

This command will:
- Create the config file if it doesn't exist (using default settings)
- Open the file in your system's default text editor:
  - **Windows**: Opens in Notepad
  - **macOS**: Opens in default text editor
  - **Linux**: Uses `$EDITOR` or `$VISUAL` environment variable, or falls back to nano/vim/vi

#### Running with Custom Config

To run with a specific configuration file:

```bash
go-pcap2socks /path/to/custom-config.json
```

Note: the `config` subcommand always edits `config.json` next to the executable; it does not take a path argument.

#### Environment Variables

- `SLOG_LEVEL`: log level - `debug`, `info`, `warn` or `error` (default: `info`)

### executeOnStart

A single command to execute when the application starts. Useful for starting a local VPN connection for example.

```json
"executeOnStart": [
  "sing-box", "run", "-c", "/etc/sing-box/config.json"
]
```

- Type: Array of strings
- Optional: Yes
- Default: Empty array
- The first element is the executable, the remaining elements are its arguments. The command is executed directly (no shell), runs in the background, and a failure is logged but does not stop go-pcap2socks

### pcap

Controls the packet capture interface and virtual network configuration.

`network` is the virtual subnet devices join and `localIP` is go-pcap2socks' own address in it - the gateway devices point at. Capture runs in promiscuous mode with a BPF filter, so only two kinds of frames are picked up: ARP requests for `localIP` from the virtual network, and IPv4 traffic from the virtual network headed outside it. Traffic between devices on the LAN is left alone.

```json
"pcap": {
  "interfaceGateway": "192.168.1.10",
  "mtu": 1500,
  "network": "172.26.0.0/16",
  "localIP": "172.26.0.1",
  "localMAC": "aa:bb:cc:dd:ee:ff"
}
```

#### Fields:

- **interfaceGateway**
  - Type: String (IPv4 address)
  - Optional: Yes
  - Default: auto-discovered (the interface holding the default route)
  - Description: IPv4 address of the physical network interface to capture on. Note this is an IP address assigned to the interface, not an interface name like "en0"

- **mtu**
  - Type: Number
  - Optional: Yes
  - Default: the capture interface's MTU
  - Description: Maximum Transmission Unit size for packets

- **network**
  - Type: String (CIDR notation)
  - Required: Yes
  - Example: "172.26.0.0/16"
  - Description: Virtual network address range

- **localIP**
  - Type: String
  - Required: Yes
  - Example: "172.26.0.1"
  - Description: Local IP address within the virtual network

- **localMAC**
  - Type: String
  - Optional: Yes
  - Default: the capture interface's MAC address
  - Format: "aa:bb:cc:dd:ee:ff" (must be a 6 byte ethernet address)
  - Description: MAC address for the virtual interface

### dns

Configures the DNS servers used by the `dns` outbound. When a device's DNS query is routed to that outbound (see the examples, which route `dstPort: "53"` there), go-pcap2socks answers the query itself: servers are tried in order and the first successful answer wins.

```json
"dns": {
  "servers": [
    {
      "address": "local"
    },
    {
      "address": "8.8.8.8:53"
    },
    {
      "address": "1.1.1.1:53"
    }
  ]
}
```

#### Fields:

- **servers**
  - Type: Array of objects
  - Optional: Yes
  - Description: List of DNS servers to try in order (first successful answer wins)

- **servers[].address**
  - Type: String
  - Required: Yes
  - Values: "local" or "host:port" (e.g. "8.8.8.8:53" - the port is not optional)
  - Description: DNS server address. "local" resolves through the operating system's own DNS configuration, which is what makes sharing a VPN work: queries follow whatever resolver the VPN pushed to the host

### routing

Defines rules for routing traffic to different outbounds based on matching criteria.

**Criteria inside a single rule are combined with OR, not AND**: the rule matches as soon as any one of its criteria matches. To require several conditions at once, they cannot be expressed in one rule. A rule with no criteria never matches anything (there is no catch-all rule; unmatched traffic goes to the default outbound).

```json
"routing": {
  "rules": [
    {
      "dstPort": "80,443",
      "dstIP": ["10.0.0.0/8", "172.16.0.0/12"],
      "outboundTag": "proxy"
    }
  ]
}
```

This example sends traffic to the "proxy" outbound if the destination port is 80 or 443, **or** the destination IP is in one of the listed networks.

#### Fields:

- **rules**
  - Type: Array of rule objects
  - Optional: Yes
  - Description: Ordered list of routing rules (first match wins). Every referenced outboundTag must exist, otherwise startup fails

#### Rule Object Fields:

- **srcPort**
  - Type: String
  - Optional: Yes
  - Format: "80" or "80,443" or "1000-2000"
  - Description: Source port(s) to match

- **dstPort**
  - Type: String
  - Optional: Yes
  - Format: Same as srcPort
  - Description: Destination port(s) to match

- **srcIP**
  - Type: Array of strings
  - Optional: Yes
  - Format: ["192.168.1.1"] or ["192.168.0.0/24"]
  - Description: Source IP addresses/CIDRs to match

- **dstIP**
  - Type: Array of strings
  - Optional: Yes
  - Format: Same as srcIP
  - Description: Destination IP addresses/CIDRs to match

- **outboundTag**
  - Type: String
  - Required: Yes
  - Description: Tag of the outbound to use for matching traffic

#### Port Format Examples:
- Single port: `"80"`
- Multiple ports: `"80,443,8080"`
- Port range: `"1000-2000"`
- Combined: `"80,443,1000-2000,3000"`

#### IP Format Examples:
- Single IP: `["192.168.1.1"]` (automatically treated as /32; a bare IPv6 address becomes /128)
- CIDR: `["192.168.0.0/24"]`
- Multiple: `["192.168.0.0/24", "10.0.0.0/8", "172.16.0.0/12"]`

### outbounds

Defines handlers for outgoing traffic. Each outbound has a tag for routing reference. **Exactly one outbound must have an empty tag (`""`); it is the default route for all unmatched traffic, and startup fails without it.** Duplicate tags are also a startup error.

```json
"outbounds": [
  {
    "tag": "",
    "direct": {}
  },
  {
    "tag": "proxy",
    "socks": {
      "address": "127.0.0.1:1080",
      "username": "user",
      "password": "pass"
    }
  },
  {
    "tag": "dns-out",
    "dns": {}
  },
  {
    "tag": "block",
    "reject": {}
  }
]
```

#### Common Fields:

- **tag**
  - Type: String
  - Optional: Yes (omitted or empty means this is the default outbound)
  - Description: Identifier for routing. **Empty string (`""`) denotes the default outbound; exactly one outbound must have it**

#### Outbound Types:

##### Direct
Routes traffic directly to the internet without proxy. Connections are dialled by the host's own network stack, so the device effectively shares the host's connectivity - including any VPN running on the host.

```json
{
  "tag": "direct",
  "direct": {}
}
```

##### SOCKS
Routes traffic through a SOCKS5 proxy. Both TCP (CONNECT) and UDP (UDP ASSOCIATE) are supported; for game consoles the proxy server must support UDP ASSOCIATE.

```json
{
  "tag": "proxy",
  "socks": {
    "address": "proxy.example.com:1080",
    "username": "optional-username",
    "password": "optional-password"
  }
}
```

- **address**: Required. Proxy server address and port. An address starting with `/` is treated as a Unix domain socket path
- **username**: Optional. For SOCKS5 authentication
- **password**: Optional. For SOCKS5 authentication

##### DNS
Special handler for DNS queries: go-pcap2socks answers matched UDP queries itself, using the servers from the [dns](#dns) section. Route `dstPort: "53"` to it (see the examples). TCP connections routed here are accepted and immediately closed.

```json
{
  "tag": "dns-out",
  "dns": {}
}
```

##### Reject
Blocks matching traffic. TCP connections are accepted and immediately closed (the client sees EOF, not a refused connection); UDP packets are silently dropped.

```json
{
  "tag": "block",
  "reject": {}
}
```

### capture

Debug feature for capturing packets to a file for analysis. Captures all Ethernet frames (including MAC addresses) in both directions, before any translation - useful to see exactly what a device sent. The file is standard pcap, readable in Wireshark.

```json
"capture": {
  "enabled": true,
  "outputFile": "capture-debug.pcap"
}
```

#### Fields:

- **enabled**
  - Type: Boolean
  - Optional: Yes
  - Default: false
  - Description: Enable/disable packet capture

- **outputFile**
  - Type: String
  - Optional: Yes
  - Default: "capture_YYYYMMDD_HHMMSS.pcap"
  - Description: Path to save captured packets. A timestamp is automatically inserted before the extension to prevent overwriting, so "debug-session.pcap" is written as "debug-session_YYYYMMDD_HHMMSS.pcap"

### Complete Example Configurations

#### Minimal Configuration

```json
{
  "pcap": {
    "mtu": 1500,
    "network": "172.26.0.0/16",
    "localIP": "172.26.0.1"
  },
  "dns": {
    "servers": [
      {
        "address": "local"
      }
    ]
  },
  "routing": {
    "rules": [
      {
        "dstPort": "53",
        "outboundTag": "dns-out"
      }
    ]
  },
  "outbounds": [
    {
      "tag": "",
      "direct": {}
    },
    {
      "tag": "dns-out",
      "dns": {}
    }
  ]
}
```

#### SOCKS Proxy for All Traffic

```json
{
  "pcap": {
    "mtu": 1500,
    "network": "172.26.0.0/16",
    "localIP": "172.26.0.1"
  },
  "dns": {
    "servers": [
      {
        "address": "8.8.8.8:53"
      }
    ]
  },
  "routing": {
    "rules": [
      {
        "dstPort": "53",
        "outboundTag": "dns-out"
      }
    ]
  },
  "outbounds": [
    {
      "tag": "",
      "socks": {
        "address": "127.0.0.1:1080"
      }
    },
    {
      "tag": "dns-out",
      "dns": {}
    }
  ]
}
```

#### Complex Routing Rules

```json
{
  "executeOnStart": [
    "ip", "route", "add", "172.26.0.0/16", "dev", "utun0"
  ],
  "pcap": {
    "interfaceGateway": "192.168.1.10",
    "mtu": 1500,
    "network": "172.26.0.0/16",
    "localIP": "172.26.0.1"
  },
  "dns": {
    "servers": [
      {
        "address": "local"
      }
    ]
  },
  "routing": {
    "rules": [
      {
        "dstPort": "53",
        "outboundTag": "dns-out"
      },
      {
        "dstIP": ["192.168.0.0/16", "10.0.0.0/8"],
        "outboundTag": "direct"
      },
      {
        "dstPort": "80,443",
        "outboundTag": "proxy"
      },
      {
        "srcIP": ["172.26.0.100"],
        "outboundTag": "block"
      }
    ]
  },
  "outbounds": [
    {
      "tag": "",
      "direct": {}
    },
    {
      "tag": "direct",
      "direct": {}
    },
    {
      "tag": "proxy",
      "socks": {
        "address": "proxy.example.com:1080",
        "username": "user",
        "password": "pass"
      }
    },
    {
      "tag": "dns-out",
      "dns": {}
    },
    {
      "tag": "block",
      "reject": {}
    }
  ]
}
```

#### Debug Configuration with Capture

```json
{
  "pcap": {
    "mtu": 1500,
    "network": "172.26.0.0/16",
    "localIP": "172.26.0.1"
  },
  "dns": {
    "servers": [
      {
        "address": "local"
      }
    ]
  },
  "routing": {
    "rules": [
      {
        "dstPort": "53",
        "outboundTag": "dns-out"
      }
    ]
  },
  "outbounds": [
    {
      "tag": "",
      "direct": {}
    },
    {
      "tag": "dns-out",
      "dns": {}
    }
  ],
  "capture": {
    "enabled": true,
    "outputFile": "debug-session.pcap"
  }
}
```

## Troubleshooting

### Permission Denied
- Run with `sudo` or as administrator
- On macOS/Linux: `sudo go-pcap2socks`
- On Windows: Run as Administrator

### Game Console Setup
For **Nintendo Switch** and **PS5**, you need to manually set the MTU value in the console's network settings. The required MTU value is displayed when go-pcap2socks starts (shown in the console output).

## Credits
- https://github.com/google/gvisor - TCP/IP stack
- https://github.com/zhxie/pcap2socks - Idea
- https://github.com/xjasonlyu/tun2socks - socks5 client
- https://github.com/SagerNet/sing-box Full Cone NAT
