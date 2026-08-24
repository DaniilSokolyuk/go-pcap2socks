package e2e

import (
	"net"
	"testing"
	"time"

	"github.com/DaniilSokolyuk/go-pcap2socks/core"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// arpRequest builds an ARP request frame asking who has target.
func arpRequest(t *testing.T, srcMAC net.HardwareAddr, srcIP, target net.IP) []byte {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       layers.EthernetBroadcast,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstProtAddress:    target.To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, eth, arp))

	return buf.Bytes()
}

// awaitARPReply waits for an ARP reply announcing target on the wire.
func awaitARPReply(t *testing.T, h *Harness, target net.IP, timeout time.Duration) *layers.ARP {
	t.Helper()

	deadline := time.After(timeout)
	for {
		select {
		case frame := <-h.Source.Outbound():
			pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
			arp, ok := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
			if !ok || arp.Operation != layers.ARPReply {
				continue
			}
			if net.IP(arp.SourceProtAddress).Equal(target) {
				return arp
			}
		case <-deadline:
			return nil
		}
	}
}

// TestGratuitousARPOnStart checks the announcement the device emits when it
// opens is a well formed ARP frame. It used to carry an IPv4 ethertype, which
// made receivers ignore it.
func TestGratuitousARPOnStart(t *testing.T) {
	h := StartRaw(t, NewConfig().Reject("").Build(t))

	var frame []byte
	select {
	case frame = <-h.Source.Outbound():
	case <-time.After(2 * time.Second):
		t.Fatal("no gratuitous ARP was sent")
	}

	eth := header.Ethernet(frame)
	assert.Equal(t, header.ARPProtocolNumber, eth.Type(), "gratuitous ARP must use the ARP ethertype")

	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	arp, ok := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
	require.True(t, ok, "frame must parse as ARP")
	assert.Equal(t, net.ParseIP(DefaultGatewayIP).To4(), net.IP(arp.SourceProtAddress).To4())
	assert.Equal(t, arp.SourceProtAddress, arp.DstProtAddress, "an announcement targets its own address")
}

// TestARPReplyForGateway checks the stack answers ARP for the gateway address.
func TestARPReplyForGateway(t *testing.T) {
	h := StartRaw(t, NewConfig().Reject("").Build(t))

	// Drain the gratuitous announcement emitted on open.
	drain(h)

	gatewayIP := net.ParseIP(DefaultGatewayIP)
	h.Source.Inject(arpRequest(t, clientMAC, net.ParseIP(DefaultClientIP), gatewayIP))

	reply := awaitARPReply(t, h, gatewayIP, 2*time.Second)
	require.NotNil(t, reply, "the gateway must answer ARP for itself")
	assert.Equal(t, gatewayMAC, net.HardwareAddr(reply.SourceHwAddress))
	assert.Equal(t, clientMAC, net.HardwareAddr(reply.DstHwAddress))
}

// TestARPForOtherHostIsIgnored checks the device drops ARP that is not aimed at
// the gateway. The stack runs with spoofing on and would otherwise answer for
// every address in the world; the device level filter is what prevents it.
func TestARPForOtherHostIsIgnored(t *testing.T) {
	h := StartRaw(t, NewConfig().Reject("").Build(t))
	drain(h)

	other := net.IPv4(172, 26, 0, 99)
	h.Source.Inject(arpRequest(t, clientMAC, net.ParseIP(DefaultClientIP), other))

	assert.Nil(t, awaitARPReply(t, h, other, 500*time.Millisecond),
		"the device must not answer ARP for addresses other than the gateway")
}

// TestARPFromOutsideNetworkIsIgnored checks frames from a foreign network are
// dropped even if they target the gateway.
func TestARPFromOutsideNetworkIsIgnored(t *testing.T) {
	h := StartRaw(t, NewConfig().Reject("").Build(t))
	drain(h)

	gatewayIP := net.ParseIP(DefaultGatewayIP)
	foreign := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x42}
	h.Source.Inject(arpRequest(t, foreign, net.IPv4(10, 1, 2, 3), gatewayIP))

	assert.Nil(t, awaitARPReply(t, h, gatewayIP, 500*time.Millisecond),
		"only devices inside the configured network are served")
}

// TestMACLearning checks that seeing traffic from a device installs a static
// neighbor entry, which is what lets the stack answer without ARPing back.
func TestMACLearning(t *testing.T) {
	h := StartRaw(t, NewConfig().Reject("").Build(t))
	drain(h)

	clientIP := net.ParseIP(DefaultClientIP)
	h.Source.Inject(arpRequest(t, clientMAC, clientIP, net.ParseIP(DefaultGatewayIP)))

	require.Eventually(t, func() bool {
		neighbors, err := h.Engine.Stack.Neighbors(core.NicID, header.IPv4ProtocolNumber)
		if err != nil {
			return false
		}
		for _, n := range neighbors {
			if n.Addr == tcpip.AddrFrom4Slice(clientIP.To4()) {
				return n.LinkAddr == tcpip.LinkAddress(clientMAC)
			}
		}
		return false
	}, 2*time.Second, 20*time.Millisecond, "the client's MAC must be learned")
}

// drain consumes whatever the device has already put on the wire.
func drain(h *Harness) {
	for {
		select {
		case <-h.Source.Outbound():
		case <-time.After(50 * time.Millisecond):
			return
		}
	}
}
