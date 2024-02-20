package proxy

import (
	"context"
	"fmt"
	"net"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	M "github.com/DaniilSokolyuk/go-pcap2socks/md"
)

var _ Proxy = (*Router)(nil)

type Router struct {
	*Base
	Rules   []cfg.Rule
	Proxies map[string]Proxy
}

func NewRouter(rules []cfg.Rule, proxies map[string]Proxy) *Router {
	return &Router{
		Rules:   rules,
		Proxies: proxies,
		Base: &Base{
			mode: ModeRouter,
		},
	}
}

func (d *Router) DialContext(ctx context.Context, metadata *M.Metadata) (net.Conn, error) {
	for _, rule := range d.Rules {
		if match(metadata, rule) {
			if proxy, ok := d.Proxies[rule.OutboundTag]; ok {
				return proxy.DialContext(ctx, metadata)
			}

			return nil, fmt.Errorf("proxy %s not found", rule.OutboundTag)
		}
	}

	return d.Proxies[""].DialContext(ctx, metadata)
}

func (d *Router) DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	for _, rule := range d.Rules {
		if match(metadata, rule) {
			if proxy, ok := d.Proxies[rule.OutboundTag]; ok {
				return proxy.DialUDP(metadata)
			}

			return nil, fmt.Errorf("proxy %s not found", rule.OutboundTag)
		}
	}

	return d.Proxies[""].DialUDP(metadata)
}

func match(metadata *M.Metadata, rule cfg.Rule) bool {
	if _, ok := rule.SrcPorts[metadata.SrcPort]; ok {
		return true
	}
	if _, ok := rule.DstPorts[metadata.DstPort]; ok {
		return true
	}
	for _, ip := range rule.SrcIPs {
		if ip.Contains(metadata.SrcIP) {
			return true
		}
	}
	for _, ip := range rule.DstIPs {
		if ip.Contains(metadata.DstIP) {
			return true
		}
	}

	return false
}
