package dns

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func addrs(list ...string) []netip.Addr {
	out := make([]netip.Addr, len(list))
	for i, s := range list {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestSystemServers(t *testing.T) {
	tests := []struct {
		name     string
		adapters []adapter
		want     []string
	}{
		{
			name: "a vpn's resolver comes before the physical adapter's",
			adapters: []adapter{
				{up: true, metric: 25, servers: addrs("192.168.1.1")},
				{up: true, metric: 5, servers: addrs("10.8.0.1")},
			},
			want: []string{"10.8.0.1", "192.168.1.1"},
		},
		{
			name: "adapters that are down or loopback are ignored",
			adapters: []adapter{
				{up: false, metric: 1, servers: addrs("10.0.0.1")},
				{up: true, loopback: true, metric: 1, servers: addrs("127.0.0.1")},
				{up: true, metric: 25, servers: addrs("192.168.1.1")},
			},
			want: []string{"192.168.1.1"},
		},
		{
			name: "a server listed on two adapters is tried once",
			adapters: []adapter{
				{up: true, metric: 5, servers: addrs("1.1.1.1", "8.8.8.8")},
				{up: true, metric: 25, servers: addrs("8.8.8.8", "192.168.1.1")},
			},
			want: []string{"1.1.1.1", "8.8.8.8", "192.168.1.1"},
		},
		{
			name: "deprecated site local anycast servers are skipped",
			adapters: []adapter{
				{up: true, metric: 25, servers: addrs("fec0:0:0:ffff::1", "192.168.1.1", "2606:4700:4700::1111")},
			},
			want: []string{"192.168.1.1", "2606:4700:4700::1111"},
		},
		{
			name: "equal metrics keep the order the system reported",
			adapters: []adapter{
				{up: true, metric: 25, servers: addrs("192.168.1.1")},
				{up: true, metric: 25, servers: addrs("192.168.2.1")},
			},
			want: []string{"192.168.1.1", "192.168.2.1"},
		},
		{name: "nothing usable", adapters: []adapter{{up: true, metric: 1}}, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, systemServers(tt.adapters))
		})
	}
}

func TestServerAddress(t *testing.T) {
	assert.Equal(t, "8.8.8.8:53", serverAddress("8.8.8.8", "53"))
	assert.Equal(t, "[2606:4700:4700::1111]:53", serverAddress("2606:4700:4700::1111", "53"))
	assert.Equal(t, "[fe80::1%12]:53", serverAddress("fe80::1%12", "53"))
	assert.Equal(t, "[::1]:5353", serverAddress("[::1]", "5353"))
}
