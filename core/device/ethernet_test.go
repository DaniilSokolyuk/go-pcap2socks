package device

import (
	"io"
	"net"
	"testing"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var (
	testGatewayIP  = net.IPv4(172, 26, 0, 1).To4()
	testGatewayMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	testClientIP   = net.IPv4(172, 26, 0, 5).To4()
	testClientMAC  = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x05}
)

// fakeStacker records the neighbors the device installs.
type fakeStacker struct {
	neighbors map[string]tcpip.LinkAddress
}

func (f *fakeStacker) AddStaticNeighbor(_ tcpip.NICID, _ tcpip.NetworkProtocolNumber, addr tcpip.Address, linkAddr tcpip.LinkAddress) tcpip.Error {
	f.neighbors[net.IP(addr.AsSlice()).String()] = linkAddr
	return nil
}

func (f *fakeStacker) AddProtocolAddress(tcpip.NICID, tcpip.ProtocolAddress, stack.AddressProperties) tcpip.Error {
	return nil
}

// newTestDevice returns a device on an in-memory segment plus its source and
// the stacker that records neighbor updates.
func newTestDevice(t *testing.T) (*ethDevice, *MemSource, *fakeStacker) {
	t.Helper()

	_, network, err := net.ParseCIDR("172.26.0.0/16")
	require.NoError(t, err)

	src := NewMemSource(16)
	stacker := &fakeStacker{neighbors: map[string]tcpip.LinkAddress{}}

	dev, err := OpenWithSource(cfg.Capture{}, src, "mem", &NetworkConfig{
		Network:  network,
		LocalIP:  testGatewayIP,
		LocalMAC: testGatewayMAC,
		MTU:      1500,
	}, func() Stacker { return stacker })
	require.NoError(t, err)
	t.Cleanup(dev.Close)

	// Drop the gratuitous announcement emitted on open.
	<-src.Outbound()

	return dev.(*ethDevice), src, stacker
}

func ipv4Frame(t *testing.T, srcMAC net.HardwareAddr, srcIP, dstIP net.IP) []byte {
	t.Helper()

	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: testGatewayMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: srcIP, DstIP: dstIP, Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 1234, DstPort: 5678}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload("hi")))

	return buf.Bytes()
}

func arpFrame(t *testing.T, srcMAC net.HardwareAddr, srcIP, target net.IP) []byte {
	t.Helper()

	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: layers.EthernetBroadcast, EthernetType: layers.EthernetTypeARP}
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
		SourceHwAddress: srcMAC, SourceProtAddress: srcIP.To4(),
		DstHwAddress: net.HardwareAddr{0, 0, 0, 0, 0, 0}, DstProtAddress: target.To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, eth, arp))

	return buf.Bytes()
}

func TestDeviceAcceptsTrafficFromTheNetwork(t *testing.T) {
	dev, src, stacker := newTestDevice(t)

	frame := ipv4Frame(t, testClientMAC, testClientIP, net.IPv4(8, 8, 8, 8))
	src.Inject(frame)

	got, err := dev.Read()
	require.NoError(t, err)
	assert.Equal(t, frame, got)
	assert.Equal(t, tcpip.LinkAddress(testClientMAC), stacker.neighbors["172.26.0.5"], "the sender's MAC is learned")
}

func TestDeviceDropsTrafficFromOtherNetworks(t *testing.T) {
	dev, src, stacker := newTestDevice(t)

	src.Inject(ipv4Frame(t, testClientMAC, net.IPv4(10, 1, 2, 3), net.IPv4(8, 8, 8, 8)))

	got, err := dev.Read()
	require.NoError(t, err)
	assert.Nil(t, got, "the frame is dropped")
	assert.Empty(t, stacker.neighbors)
}

func TestDeviceDoesNotLearnItsOwnAddress(t *testing.T) {
	dev, src, stacker := newTestDevice(t)

	src.Inject(ipv4Frame(t, testGatewayMAC, testGatewayIP, net.IPv4(8, 8, 8, 8)))

	got, err := dev.Read()
	require.NoError(t, err)
	assert.NotNil(t, got, "our own traffic still passes through")
	assert.Empty(t, stacker.neighbors, "we must not add ourselves as a neighbor")
}

func TestDeviceAcceptsARPForTheGateway(t *testing.T) {
	dev, src, stacker := newTestDevice(t)

	frame := arpFrame(t, testClientMAC, testClientIP, testGatewayIP)
	src.Inject(frame)

	got, err := dev.Read()
	require.NoError(t, err)
	assert.Equal(t, frame, got)
	assert.Equal(t, tcpip.LinkAddress(testClientMAC), stacker.neighbors["172.26.0.5"])
}

func TestDeviceDropsARPForOtherTargets(t *testing.T) {
	dev, src, stacker := newTestDevice(t)

	src.Inject(arpFrame(t, testClientMAC, testClientIP, net.IPv4(172, 26, 0, 99)))

	got, err := dev.Read()
	require.NoError(t, err)
	assert.Nil(t, got, "ARP not aimed at the gateway is dropped")
	assert.Empty(t, stacker.neighbors)
}

func TestDeviceDropsUnknownEthertypes(t *testing.T) {
	dev, src, _ := newTestDevice(t)

	eth := &layers.Ethernet{SrcMAC: testClientMAC, DstMAC: testGatewayMAC, EthernetType: layers.EthernetTypeIPv6}
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, eth, gopacket.Payload("junk")))
	src.Inject(buf.Bytes())

	got, err := dev.Read()
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestDeviceReadReportsClosedSource(t *testing.T) {
	dev, src, _ := newTestDevice(t)

	require.NoError(t, src.Close())

	_, err := dev.Read()
	assert.ErrorIs(t, err, io.EOF, "a closed source must be reported, not silently retried")
}

func TestDeviceSendsGratuitousARPOnOpen(t *testing.T) {
	_, network, err := net.ParseCIDR("172.26.0.0/16")
	require.NoError(t, err)

	src := NewMemSource(16)
	stacker := &fakeStacker{neighbors: map[string]tcpip.LinkAddress{}}

	dev, err := OpenWithSource(cfg.Capture{}, src, "mem", &NetworkConfig{
		Network: network, LocalIP: testGatewayIP, LocalMAC: testGatewayMAC, MTU: 1500,
	}, func() Stacker { return stacker })
	require.NoError(t, err)
	defer dev.Close()

	frame := <-src.Outbound()

	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	arp, ok := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
	require.True(t, ok, "the device announces itself with ARP on open")
	assert.Equal(t, testGatewayIP, net.IP(arp.SourceProtAddress))

	assert.Equal(t, "mem", dev.Type())
	assert.Equal(t, "dspcap", dev.Name())
}

func TestBPFFilter(t *testing.T) {
	_, network, err := net.ParseCIDR("172.26.0.0/16")
	require.NoError(t, err)

	filter := BPFFilter(&NetworkConfig{Network: network, LocalIP: testGatewayIP})

	assert.Equal(t,
		"(arp dst host 172.26.0.1 and arp src net 172.26.0.0/16 and not arp src host 172.26.0.1) "+
			"or (src net 172.26.0.0/16 and not dst net 172.26.0.0/16 and not (icmp and src host 172.26.0.1))",
		filter)
}
