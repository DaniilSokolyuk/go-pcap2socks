# go-pcap2socks Configuration Guide

This document describes the configuration options for go-pcap2socks. The configuration uses JSON format and is typically stored in `config.json`.

## CLI Commands

### Opening Configuration in Editor

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

### Running with Custom Config

To run with a specific configuration file:

```bash
go-pcap2socks /path/to/custom-config.json
```

## executeOnStart

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

## pcap

Controls the packet capture interface and virtual network configuration.

```json
"pcap": {
  "interfaceGateway": "192.168.1.10",
  "mtu": 1500,
  "network": "172.26.0.0/16",
  "localIP": "172.26.0.1",
  "localMAC": "aa:bb:cc:dd:ee:ff"
}
```

### Fields:

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

## dns

Configures DNS servers for domain name resolution.

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

### Fields:

- **servers**
  - Type: Array of objects
  - Optional: Yes
  - Description: List of DNS servers to try in order (first successful answer wins)

- **servers[].address**
  - Type: String
  - Required: Yes
  - Values: "local" or "host:port" (e.g. "8.8.8.8:53" - the port is not optional)
  - Description: DNS server address. "local" uses system DNS

## routing

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

### Fields:

- **rules**
  - Type: Array of rule objects
  - Optional: Yes
  - Description: Ordered list of routing rules (first match wins). Every referenced outboundTag must exist, otherwise startup fails

### Rule Object Fields:

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

### Port Format Examples:
- Single port: `"80"`
- Multiple ports: `"80,443,8080"`
- Port range: `"1000-2000"`
- Combined: `"80,443,1000-2000,3000"`

### IP Format Examples:
- Single IP: `["192.168.1.1"]` (automatically treated as /32; a bare IPv6 address becomes /128)
- CIDR: `["192.168.0.0/24"]`
- Multiple: `["192.168.0.0/24", "10.0.0.0/8", "172.16.0.0/12"]`

## outbounds

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

### Common Fields:

- **tag**
  - Type: String
  - Optional: Yes (omitted or empty means this is the default outbound)
  - Description: Identifier for routing. **Empty string (`""`) denotes the default outbound; exactly one outbound must have it**

### Outbound Types:

#### Direct
Routes traffic directly to the internet without proxy.

```json
{
  "tag": "direct",
  "direct": {}
}
```

#### SOCKS
Routes traffic through a SOCKS5 proxy.

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

#### DNS
Special handler for DNS queries.

```json
{
  "tag": "dns-out",
  "dns": {}
}
```

#### Reject
Blocks matching traffic.

```json
{
  "tag": "block",
  "reject": {}
}
```

## capture

Debug feature for capturing packets to a file for analysis. Captures all Ethernet frames (including MAC addresses) for troubleshooting.

```json
"capture": {
  "enabled": true,
  "outputFile": "capture-debug.pcap"
}
```

### Fields:

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

## Complete Example Configurations

### Minimal Configuration

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

### SOCKS Proxy for All Traffic

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

### Complex Routing Rules

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

### Debug Configuration with Capture

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