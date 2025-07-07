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

Commands to execute when the application starts. Useful for starting local VPN connections for example.

```json
"executeOnStart": [
  "echo 'Starting pcap2socks and VPN'",
  "sing-box run -c /etc/sing-box/config.json"
]
```

- Type: Array of strings
- Optional: Yes
- Default: Empty array
- Each string is executed as a shell command in order

## pcap

Controls the packet capture interface and virtual network configuration.

```json
"pcap": {
  "interfaceGateway": "en0",
  "mtu": 1500,
  "network": "172.26.0.0/16",
  "localIP": "172.26.0.1",
  "localMAC": "aa:bb:cc:dd:ee:ff"
}
```

### Fields:

- **interfaceGateway**
  - Type: String
  - Optional: Yes
  - Description: Physical network interface to use as gateway

- **mtu**
  - Type: Number
  - Required: Yes
  - Default: 1500
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
  - Format: "aa:bb:cc:dd:ee:ff"
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
      "address": "8.8.8.8"
    },
    {
      "address": "1.1.1.1"
    }
  ]
}
```

### Fields:

- **servers**
  - Type: Array of objects
  - Required: Yes
  - Description: List of DNS servers to use

- **servers[].address**
  - Type: String
  - Required: Yes
  - Values: "local" or IP address
  - Description: DNS server address. "local" uses system DNS

## routing

Defines rules for routing traffic to different outbounds based on matching criteria.

```json
"routing": {
  "rules": [
    {
      "srcPort": "1024-65535",
      "dstPort": "80,443",
      "srcIP": ["192.168.1.0/24"],
      "dstIP": ["10.0.0.0/8", "172.16.0.0/12"],
      "outboundTag": "proxy"
    }
  ]
}
```

### Fields:

- **rules**
  - Type: Array of rule objects
  - Required: Yes
  - Description: Ordered list of routing rules (first match wins)

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
- Single IP: `["192.168.1.1"]` (automatically treated as /32)
- CIDR: `["192.168.0.0/24"]`
- Multiple: `["192.168.0.0/24", "10.0.0.0/8", "172.16.0.0/12"]`

## outbounds

Defines handlers for outgoing traffic. Each outbound has a tag for routing reference. **An outbound with an empty tag (`""`) serves as the default route for all unmatched traffic.**

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
  - Required: Yes
  - Description: Identifier for routing. **Empty string (`""`) denotes default outbound**

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
Routes traffic through a SOCKS4/SOCKS5 proxy.

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

- **address**: Required. Proxy server address and port
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

Debug feature for capturing packets to a file for analysis.

```json
"capture": {
  "enabled": true,
  "targetIP": "172.26.0.5",
  "outputFile": "capture-debug.pcap"
}
```

### Fields:

- **enabled**
  - Type: Boolean
  - Required: Yes
  - Default: false
  - Description: Enable/disable packet capture

- **targetIP**
  - Type: String
  - Required: Yes (when enabled)
  - Description: IP address to capture packets from

- **outputFile**
  - Type: String
  - Required: Yes (when enabled)
  - Default: "debug-capture.pcap"
  - Description: Path to save captured packets

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
        "address": "8.8.8.8"
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
    "ip route add 172.26.0.0/16 dev utun0"
  ],
  "pcap": {
    "interfaceGateway": "en0",
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
    "targetIP": "172.26.0.5",
    "outputFile": "debug-session.pcap"
  }
}
```