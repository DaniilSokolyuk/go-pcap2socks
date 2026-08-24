package socks5

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSerializeAddr(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		ip     net.IP
		port   uint16
		want   []byte
	}{
		{
			name: "ipv4",
			ip:   net.IPv4(1, 2, 3, 4),
			port: 443,
			want: []byte{AtypIPv4, 1, 2, 3, 4, 0x01, 0xbb},
		},
		{
			name: "ipv6",
			ip:   net.ParseIP("2001:db8::1"),
			port: 80,
			want: append([]byte{AtypIPv6}, append(net.ParseIP("2001:db8::1").To16(), 0x00, 0x50)...),
		},
		{
			name:   "domain",
			domain: "example.com",
			port:   8080,
			want:   append([]byte{AtypDomainName, 11}, append([]byte("example.com"), 0x1f, 0x90)...),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, Addr(tc.want), SerializeAddr(tc.domain, tc.ip, tc.port))
		})
	}
}

func TestParseAddrRoundTrip(t *testing.T) {
	tests := []net.Addr{
		&net.TCPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 80},
		&net.UDPAddr{IP: net.IPv4(203, 0, 113, 20), Port: 9000},
		&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 53},
	}

	for _, addr := range tests {
		t.Run(addr.String(), func(t *testing.T) {
			parsed := ParseAddr(addr)
			require.NotNil(t, parsed)
			assert.Equal(t, addr.String(), parsed.String())
		})
	}
}

func TestParseAddrStringInvalid(t *testing.T) {
	assert.Nil(t, ParseAddrString("no-port"))
	assert.Nil(t, ParseAddrString("host:not-a-port"))
}

func TestUDPPacketRoundTrip(t *testing.T) {
	addr := SerializeAddr("", net.IPv4(203, 0, 113, 10), 9000)
	payload := []byte("payload bytes")

	packet, err := EncodeUDPPacket(addr, payload)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x00, 0x00, 0x00}, packet[:3], "RSV and FRAG are zero")

	gotAddr, gotPayload, err := DecodeUDPPacket(packet)
	require.NoError(t, err)
	assert.Equal(t, addr, gotAddr)
	assert.Equal(t, payload, gotPayload)
	assert.Equal(t, "203.0.113.10:9000", gotAddr.UDPAddr().String())
}

func TestEncodeUDPPacketRejectsNilAddr(t *testing.T) {
	_, err := EncodeUDPPacket(nil, []byte("x"))
	require.Error(t, err)
}

func TestDecodeUDPPacketRejectsBadInput(t *testing.T) {
	addr := SerializeAddr("", net.IPv4(1, 2, 3, 4), 80)
	valid, err := EncodeUDPPacket(addr, []byte("data"))
	require.NoError(t, err)

	t.Run("too short", func(t *testing.T) {
		_, _, err := DecodeUDPPacket([]byte{0, 0})
		require.Error(t, err)
	})

	t.Run("reserved fields must be zero", func(t *testing.T) {
		bad := append([]byte(nil), valid...)
		bad[0] = 0x01
		_, _, err := DecodeUDPPacket(bad)
		require.Error(t, err)
	})

	t.Run("fragments are refused", func(t *testing.T) {
		bad := append([]byte(nil), valid...)
		bad[2] = 0x01
		_, _, err := DecodeUDPPacket(bad)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "fragmented")
	})

	t.Run("unknown address type", func(t *testing.T) {
		bad := append([]byte(nil), valid...)
		bad[3] = 0x09
		_, _, err := DecodeUDPPacket(bad)
		require.Error(t, err)
	})

	t.Run("truncated address", func(t *testing.T) {
		_, _, err := DecodeUDPPacket(valid[:6])
		require.Error(t, err)
	})
}

func FuzzDecodeUDPPacket(f *testing.F) {
	addr := SerializeAddr("", net.IPv4(1, 2, 3, 4), 80)
	valid, err := EncodeUDPPacket(addr, []byte("data"))
	if err != nil {
		f.Fatal(err)
	}

	f.Add(valid)
	f.Add([]byte{0x00, 0x00, 0x00, AtypDomainName, 0xff})
	f.Add([]byte{0x00, 0x00, 0x00, AtypIPv6})

	f.Fuzz(func(t *testing.T, packet []byte) {
		// Must never panic, whatever the input.
		gotAddr, _, err := DecodeUDPPacket(packet)
		if err == nil && gotAddr != nil {
			_ = gotAddr.String()
			_ = gotAddr.UDPAddr()
		}
	})
}
