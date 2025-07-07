# go-pcap2socks
go-pcap2socks is a proxy that redirects traffic from any device to a SOCKS5 proxy.

go-pcap2socks functions like a router, allowing you to connect various devices such as an **XBOX**, **PlayStation (PS4, PS5)**, **Nintendo Switch**, mobile phones, printers and others to any SOCKS5 proxy server. Additionally, you can just start go-pcap2socks with the default direct outbound to share your VPN connection to any devices on your network.

## Documentation

- [Installation Guide](install.md) - Instructions for installing go-pcap2socks on various platforms
- [Configuration Guide](config.md) - Detailed configuration documentation with examples

## Quick Start

```bash
# Install
go install github.com/DaniilSokolyuk/go-pcap2socks@latest

# Configure
go-pcap2socks config

# Run
sudo go-pcap2socks
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
