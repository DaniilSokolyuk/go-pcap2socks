# go-pcap2socks
go-pcap2socks is a proxy that redirects traffic from any device to a SOCKS5 proxy.

go-pcap2socks functions like a router, allowing you to connect various devices such as an **XBOX**, **PlayStatation**, **Nintendo Switch**, printer and others to any SOCKS5 proxy server. Additionally, you can host a SOCKS5 proxy server on the same PC to use services like a VPN or a game booster/accelerator for reduced latency.

## Dependencies
 [Npcap](http://www.npcap.org/) or WinPcap in Windows (If using Npcap, make sure to install with the "Install Npcap in WinPcap API-compatible Mode"), libpcap in macOS, Linux and others.

## Config
Config example is [here](https://github.com/DaniilSokolyuk/go-pcap2socks/blob/main/config.json)

## Credits
- https://github.com/zhxie/pcap2socks - Idea
- https://github.com/xjasonlyu/tun2socks - Forked from
- https://github.com/SagerNet/sing-box Full Cone NAT
