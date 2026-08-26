package proxy

import (
	"context"
	"net"
	"testing"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	M "github.com/DaniilSokolyuk/go-pcap2socks/md"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingProxy notes which one of several outbounds a connection reached.
type recordingProxy struct {
	*Base
	tag    string
	picked *string
}

func (p *recordingProxy) DialContext(context.Context, *M.Metadata) (net.Conn, error) {
	*p.picked = p.tag
	return &nopConn{}, nil
}

func (p *recordingProxy) DialUDP(*M.Metadata) (net.PacketConn, error) {
	*p.picked = p.tag
	return &nopPacketConn{}, nil
}

func mustRule(t *testing.T, rule cfg.Rule) cfg.Rule {
	t.Helper()
	require.NoError(t, rule.Normalize())
	return rule
}

func metadata(src string, srcPort uint16, dst string, dstPort uint16) *M.Metadata {
	return &M.Metadata{
		Network: M.TCP,
		SrcIP:   net.ParseIP(src),
		SrcPort: srcPort,
		DstIP:   net.ParseIP(dst),
		DstPort: dstPort,
	}
}

func TestRouterSelectsOutbound(t *testing.T) {
	tests := []struct {
		name string
		rule cfg.Rule
		md   *M.Metadata
		want string
	}{
		{
			name: "destination port matches",
			rule: cfg.Rule{DstPort: "53", OutboundTag: "hit"},
			md:   metadata("172.26.0.5", 40000, "8.8.8.8", 53),
			want: "hit",
		},
		{
			name: "destination port outside range falls through",
			rule: cfg.Rule{DstPort: "8000-8100", OutboundTag: "hit"},
			md:   metadata("172.26.0.5", 40000, "8.8.8.8", 8101),
			want: "default",
		},
		{
			name: "destination port inside range matches",
			rule: cfg.Rule{DstPort: "8000-8100", OutboundTag: "hit"},
			md:   metadata("172.26.0.5", 40000, "8.8.8.8", 8100),
			want: "hit",
		},
		{
			name: "source port matches",
			rule: cfg.Rule{SrcPort: "3074", OutboundTag: "hit"},
			md:   metadata("172.26.0.5", 3074, "8.8.8.8", 443),
			want: "hit",
		},
		{
			name: "source network matches",
			rule: cfg.Rule{SrcIP: []string{"172.26.0.0/16"}, OutboundTag: "hit"},
			md:   metadata("172.26.0.5", 40000, "8.8.8.8", 443),
			want: "hit",
		},
		{
			name: "source host outside network falls through",
			rule: cfg.Rule{SrcIP: []string{"172.26.0.5"}, OutboundTag: "hit"},
			md:   metadata("172.26.0.6", 40000, "8.8.8.8", 443),
			want: "default",
		},
		{
			name: "destination network matches",
			rule: cfg.Rule{DstIP: []string{"8.8.8.0/24"}, OutboundTag: "hit"},
			md:   metadata("172.26.0.5", 40000, "8.8.8.8", 443),
			want: "hit",
		},
		{
			name: "no criteria never matches",
			rule: cfg.Rule{OutboundTag: "hit"},
			md:   metadata("172.26.0.5", 40000, "8.8.8.8", 443),
			want: "default",
		},
		{
			// Criteria inside one rule are combined with OR, not AND: any single
			// match wins. This is surprising but it is the behaviour configs in
			// the wild rely on, so it is pinned here on purpose.
			name: "criteria are ORed, not ANDed",
			rule: cfg.Rule{SrcIP: []string{"172.26.0.5"}, DstPort: "9999", OutboundTag: "hit"},
			md:   metadata("172.26.0.5", 40000, "8.8.8.8", 443),
			want: "hit",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var picked string
			proxies := map[string]Proxy{
				"":    &recordingProxy{Base: &Base{}, tag: "default", picked: &picked},
				"hit": &recordingProxy{Base: &Base{}, tag: "hit", picked: &picked},
			}

			router := NewRouter([]cfg.Rule{mustRule(t, tc.rule)}, proxies)

			_, err := router.DialContext(context.Background(), tc.md)
			require.NoError(t, err)
			assert.Equal(t, tc.want, picked, "TCP")

			picked = ""
			_, err = router.DialUDP(tc.md)
			require.NoError(t, err)
			assert.Equal(t, tc.want, picked, "UDP")
		})
	}
}

func TestRouterFirstMatchWins(t *testing.T) {
	var picked string
	proxies := map[string]Proxy{
		"":       &recordingProxy{Base: &Base{}, tag: "default", picked: &picked},
		"first":  &recordingProxy{Base: &Base{}, tag: "first", picked: &picked},
		"second": &recordingProxy{Base: &Base{}, tag: "second", picked: &picked},
	}

	router := NewRouter([]cfg.Rule{
		mustRule(t, cfg.Rule{DstPort: "443", OutboundTag: "first"}),
		mustRule(t, cfg.Rule{DstPort: "443", OutboundTag: "second"}),
	}, proxies)

	_, err := router.DialContext(context.Background(), metadata("172.26.0.5", 40000, "1.1.1.1", 443))
	require.NoError(t, err)
	assert.Equal(t, "first", picked)
}

func TestRouterUnknownOutbound(t *testing.T) {
	var picked string
	proxies := map[string]Proxy{
		"": &recordingProxy{Base: &Base{}, tag: "default", picked: &picked},
	}

	router := NewRouter([]cfg.Rule{
		mustRule(t, cfg.Rule{DstPort: "443", OutboundTag: "missing"}),
	}, proxies)

	_, err := router.DialContext(context.Background(), metadata("172.26.0.5", 40000, "1.1.1.1", 443))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")

	_, err = router.DialUDP(metadata("172.26.0.5", 40000, "1.1.1.1", 443))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
}
