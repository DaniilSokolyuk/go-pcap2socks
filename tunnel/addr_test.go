package tunnel

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseAddr(t *testing.T) {
	tests := []struct {
		name     string
		addr     net.Addr
		wantIP   net.IP
		wantPort uint16
	}{
		{
			name:     "tcp",
			addr:     &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 8080},
			wantIP:   net.IPv4(10, 0, 0, 1),
			wantPort: 8080,
		},
		{
			name:     "udp",
			addr:     &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 53},
			wantIP:   net.IPv4(10, 0, 0, 2),
			wantPort: 53,
		},
		{
			name:     "nil",
			addr:     nil,
			wantIP:   nil,
			wantPort: 0,
		},
		{
			name:     "falls back to the string form",
			addr:     stringAddr("192.0.2.1:443"),
			wantIP:   net.ParseIP("192.0.2.1"),
			wantPort: 443,
		},
		{
			name:     "ipv6 string form",
			addr:     stringAddr("[2001:db8::1]:443"),
			wantIP:   net.ParseIP("2001:db8::1"),
			wantPort: 443,
		},
		{
			name:     "unparseable string yields zero values",
			addr:     stringAddr("garbage"),
			wantIP:   nil,
			wantPort: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip, port := parseAddr(tc.addr)
			assert.Equal(t, tc.wantPort, port)
			if tc.wantIP == nil {
				assert.Nil(t, ip)
				return
			}
			assert.True(t, tc.wantIP.Equal(ip), "want %s, got %s", tc.wantIP, ip)
		})
	}
}

type stringAddr string

func (s stringAddr) Network() string { return "test" }
func (s stringAddr) String() string  { return string(s) }
