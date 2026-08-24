package engine

import (
	"net"
	"testing"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testIfce = net.Interface{
	Name:         "en0",
	MTU:          1500,
	HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01},
}

func TestParseNetworkConfig(t *testing.T) {
	t.Run("defaults come from the interface", func(t *testing.T) {
		got, err := ParseNetworkConfig(cfg.PCAP{
			Network: "172.26.0.0/16",
			LocalIP: "172.26.0.1",
		}, testIfce)
		require.NoError(t, err)

		assert.Equal(t, "172.26.0.0/16", got.Network.String())
		assert.Equal(t, net.IP{172, 26, 0, 1}, got.LocalIP)
		assert.Equal(t, testIfce.HardwareAddr, got.LocalMAC, "the interface MAC is used when none is configured")
		assert.Equal(t, uint32(1500), got.MTU)
	})

	t.Run("explicit mac and mtu win", func(t *testing.T) {
		got, err := ParseNetworkConfig(cfg.PCAP{
			Network:  "10.0.0.0/8",
			LocalIP:  "10.0.0.1",
			LocalMAC: "aa:bb:cc:dd:ee:ff",
			MTU:      1400,
		}, testIfce)
		require.NoError(t, err)

		assert.Equal(t, "aa:bb:cc:dd:ee:ff", got.LocalMAC.String())
		assert.Equal(t, uint32(1400), got.MTU)
	})

	t.Run("local ip is normalized to 4 bytes", func(t *testing.T) {
		got, err := ParseNetworkConfig(cfg.PCAP{Network: "172.26.0.0/16", LocalIP: "172.26.0.1"}, testIfce)
		require.NoError(t, err)
		assert.Len(t, got.LocalIP, 4, "ARP and the device filter both depend on this")
	})

	tests := []struct {
		name    string
		pcap    cfg.PCAP
		ifce    net.Interface
		wantErr string
	}{
		{
			name:    "bad network",
			pcap:    cfg.PCAP{Network: "not-a-cidr", LocalIP: "172.26.0.1"},
			ifce:    testIfce,
			wantErr: "parse cidr",
		},
		{
			name:    "bad local ip",
			pcap:    cfg.PCAP{Network: "172.26.0.0/16", LocalIP: "nope"},
			ifce:    testIfce,
			wantErr: "parse local ip",
		},
		{
			name:    "local ip outside the network",
			pcap:    cfg.PCAP{Network: "172.26.0.0/16", LocalIP: "10.0.0.1"},
			ifce:    testIfce,
			wantErr: "not in network",
		},
		{
			name:    "ipv6 local ip",
			pcap:    cfg.PCAP{Network: "172.26.0.0/16", LocalIP: "2001:db8::1"},
			ifce:    testIfce,
			wantErr: "must be IPv4",
		},
		{
			name:    "bad mac",
			pcap:    cfg.PCAP{Network: "172.26.0.0/16", LocalIP: "172.26.0.1", LocalMAC: "zz"},
			ifce:    testIfce,
			wantErr: "parse local mac",
		},
		{
			name:    "interface without a mac",
			pcap:    cfg.PCAP{Network: "172.26.0.0/16", LocalIP: "172.26.0.1"},
			ifce:    net.Interface{Name: "tun0", MTU: 1500},
			wantErr: "6 byte ethernet address",
		},
		{
			name:    "no mtu anywhere",
			pcap:    cfg.PCAP{Network: "172.26.0.0/16", LocalIP: "172.26.0.1"},
			ifce:    net.Interface{Name: "en0", HardwareAddr: testIfce.HardwareAddr},
			wantErr: "mtu is zero",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseNetworkConfig(tc.pcap, tc.ifce)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
