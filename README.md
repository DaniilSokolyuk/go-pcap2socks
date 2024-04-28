# go-pcap2socks
go-pcap2socks is a proxy that redirects traffic from any device to a SOCKS5 proxy.

go-pcap2socks functions like a router, allowing you to connect various devices such as an **XBOX**, **PlayStation (PS4, PS5)**, **Nintendo Switch**, mobile phones, printers and others to any SOCKS5 proxy server. Additionally, you can host a SOCKS5 proxy server on the same PC to use services like a VPN or a game booster/accelerator for reduced latency, you can also share a working VPN from your computer to your mobile phone.

## Dependencies
For **Windows**, install [Npcap](http://www.npcap.org/) or WinPcap. If you choose Npcap, ensure to install it in "WinPcap API-compatible Mode". For **macOS**, **Linux**, and other operating systems, use libpcap.

## Config
Config example is [here](https://github.com/DaniilSokolyuk/go-pcap2socks/blob/main/config.json)

## Credits
- https://github.com/zhxie/pcap2socks - Idea
- https://github.com/xjasonlyu/tun2socks - Fork
- https://github.com/SagerNet/sing-box Full Cone NAT
