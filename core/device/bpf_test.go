package device

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/bpf"
)

func filterIPv4Frame(src, dst string, proto byte) []byte {
	frame := make([]byte, 14+20+8)
	binary.BigEndian.PutUint16(frame[12:], etherTypeIPv4)
	frame[14] = 0x45
	frame[offIPv4Proto] = proto
	copy(frame[offIPv4Src:], net.ParseIP(src).To4())
	copy(frame[offIPv4Dst:], net.ParseIP(dst).To4())
	return frame
}

func filterARPFrame(sender, target string) []byte {
	frame := make([]byte, 14+28)
	binary.BigEndian.PutUint16(frame[12:], etherTypeARP)
	copy(frame[offARPSender:], net.ParseIP(sender).To4())
	copy(frame[offARPTarget:], net.ParseIP(target).To4())
	return frame
}

func TestCaptureFilter(t *testing.T) {
	_, network, err := net.ParseCIDR("172.26.0.0/16")
	require.NoError(t, err)
	raw, err := CaptureFilter(&NetworkConfig{Network: network, LocalIP: net.ParseIP("172.26.0.1")})
	require.NoError(t, err)

	instructions, ok := bpf.Disassemble(raw)
	require.True(t, ok)
	vm, err := bpf.NewVM(instructions)
	require.NoError(t, err)

	const tcp, udp, icmp = 6, 17, 1
	ipv6 := make([]byte, 60)
	binary.BigEndian.PutUint16(ipv6[12:], 0x86dd)

	tests := []struct {
		name   string
		frame  []byte
		accept bool
	}{
		{"console to the internet, tcp", filterIPv4Frame("172.26.0.5", "203.0.113.10", tcp), true},
		{"console to the internet, udp", filterIPv4Frame("172.26.0.5", "8.8.8.8", udp), true},
		{"console pinging the internet", filterIPv4Frame("172.26.0.5", "8.8.8.8", icmp), true},
		{"console to another device on the network", filterIPv4Frame("172.26.0.5", "172.26.0.9", tcp), false},
		{"console to the gateway itself", filterIPv4Frame("172.26.0.5", "172.26.0.1", icmp), false},
		{"our own icmp seen in promiscuous mode", filterIPv4Frame("172.26.0.1", "8.8.8.8", icmp), false},
		{"traffic of the host's real network", filterIPv4Frame("192.168.1.20", "203.0.113.10", tcp), false},
		{"reply we injected towards the console", filterIPv4Frame("203.0.113.10", "172.26.0.5", tcp), false},
		{"arp for the gateway", filterARPFrame("172.26.0.5", "172.26.0.1"), true},
		{"arp for somebody else", filterARPFrame("172.26.0.5", "172.26.0.9"), false},
		{"arp from the gateway address", filterARPFrame("172.26.0.1", "172.26.0.1"), false},
		{"arp for the gateway from another network", filterARPFrame("192.168.1.20", "172.26.0.1"), false},
		{"ipv6", ipv6, false},
		{"runt", []byte{1, 2, 3}, false},
		{"truncated ipv4", filterIPv4Frame("172.26.0.5", "203.0.113.10", tcp)[:20], false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := vm.Run(tt.frame)
			require.NoError(t, err)
			require.Equal(t, tt.accept, n > 0)
		})
	}
}

func TestCaptureFilterRejectsIPv6Network(t *testing.T) {
	_, network, err := net.ParseCIDR("fd00::/64")
	require.NoError(t, err)
	_, err = CaptureFilter(&NetworkConfig{Network: network, LocalIP: net.ParseIP("fd00::1")})
	require.Error(t, err)
}
