package e2e

import (
	"net/netip"
	"testing"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
)

// ConfigBuilder assembles configurations for the harness.
type ConfigBuilder struct {
	cfg cfg.Config
}

// NewConfig returns a builder with the standard pcap section and no outbounds.
func NewConfig() *ConfigBuilder {
	b := &ConfigBuilder{}
	b.cfg.PCAP = cfg.PCAP{
		Network: DefaultNetwork,
		LocalIP: DefaultGatewayIP,
		MTU:     defaultMTU,
	}
	return b
}

// Direct adds a direct outbound under tag.
func (b *ConfigBuilder) Direct(tag string) *ConfigBuilder {
	b.cfg.Outbounds = append(b.cfg.Outbounds, cfg.Outbound{Tag: tag, Direct: &cfg.OutboundDirect{}})
	return b
}

// Reject adds a reject outbound under tag.
func (b *ConfigBuilder) Reject(tag string) *ConfigBuilder {
	b.cfg.Outbounds = append(b.cfg.Outbounds, cfg.Outbound{Tag: tag, Reject: &cfg.OutboundReject{}})
	return b
}

// Socks adds a socks5 outbound under tag.
func (b *ConfigBuilder) Socks(tag string, addr netip.AddrPort, user, pass string) *ConfigBuilder {
	b.cfg.Outbounds = append(b.cfg.Outbounds, cfg.Outbound{
		Tag:   tag,
		Socks: &cfg.OutboundSocks{Address: addr.String(), Username: user, Password: pass},
	})
	return b
}

// DNSOut adds a dns outbound under tag, resolving through the given servers.
func (b *ConfigBuilder) DNSOut(tag string, servers ...netip.AddrPort) *ConfigBuilder {
	for _, server := range servers {
		b.cfg.DNS.Servers = append(b.cfg.DNS.Servers, struct {
			Address string `json:"address"`
		}{Address: server.String()})
	}
	b.cfg.Outbounds = append(b.cfg.Outbounds, cfg.Outbound{Tag: tag, DNS: &cfg.OutboundDNS{}})
	return b
}

// Rule appends a routing rule.
func (b *ConfigBuilder) Rule(rule cfg.Rule) *ConfigBuilder {
	b.cfg.Routing.Rules = append(b.cfg.Routing.Rules, rule)
	return b
}

// Build normalizes and returns the configuration.
func (b *ConfigBuilder) Build(t *testing.T) *cfg.Config {
	t.Helper()

	config := b.cfg
	if err := config.Normalize(); err != nil {
		t.Fatalf("normalize config: %v", err)
	}

	return &config
}
