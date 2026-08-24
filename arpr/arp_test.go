package arpr

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendGratuitousArp(t *testing.T) {
	localIP := net.IPv4(172, 26, 0, 1)
	localMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	frame, err := SendGratuitousArp(localIP, localMAC)
	require.NoError(t, err)

	want := []byte{
		// Ethernet: broadcast destination, our source, ARP ethertype.
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x06,
		// ARP: ethernet over IPv4, request.
		0x00, 0x01,
		0x08, 0x00,
		0x06, 0x04,
		0x00, 0x01,
		// Sender: our MAC and IP.
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
		172, 26, 0, 1,
		// Target: unknown MAC, our own IP (that is what makes it gratuitous).
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		172, 26, 0, 1,
		// Padding up to the 60 byte ethernet minimum.
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	require.Len(t, frame, 60)
	assert.Equal(t, want, frame)
}

// TestGratuitousArpEthertype guards the specific bug that made devices ignore
// the announcement: the frame carried the IPv4 ethertype with an ARP body.
func TestGratuitousArpEthertype(t *testing.T) {
	frame, err := SendGratuitousArp(net.IPv4(10, 0, 0, 1), net.HardwareAddr{1, 2, 3, 4, 5, 6})
	require.NoError(t, err)

	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

	eth, ok := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	require.True(t, ok)
	assert.Equal(t, layers.EthernetTypeARP, eth.EthernetType)

	arp, ok := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
	require.True(t, ok, "the body must parse as ARP")
	assert.Equal(t, uint16(layers.ARPRequest), arp.Operation)
	assert.Equal(t, arp.SourceProtAddress, arp.DstProtAddress)
}

func TestSendGratuitousArpIPv6MappedAddress(t *testing.T) {
	// net.ParseIP returns a 16 byte representation for IPv4 literals; the
	// serializer must still emit a 4 byte protocol address.
	frame, err := SendGratuitousArp(net.ParseIP("192.0.2.1"), net.HardwareAddr{1, 2, 3, 4, 5, 6})
	require.NoError(t, err)

	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	arp, ok := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
	require.True(t, ok)
	assert.Equal(t, net.IP{192, 0, 2, 1}, net.IP(arp.SourceProtAddress))
	assert.Equal(t, uint8(4), arp.ProtAddressSize)
}
