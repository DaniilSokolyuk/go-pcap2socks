package e2e

import (
	"net"
	"sync"
	"testing"
	"time"

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
		neighbors, err := h.Engine.Stack.Neighbors(h.Engine.NicID, header.IPv4ProtocolNumber)
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

// strayTCPSegment builds a TCP ACK from the client to an address outside the
// network, for a connection that does not exist. Delivering it makes the stack
// reply with a RST, and building that reply takes the stack lock (FindRoute).
func strayTCPSegment(t *testing.T) []byte {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       clientMAC,
		DstMAC:       gatewayMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(DefaultClientIP),
		DstIP:    net.ParseIP("203.0.113.10"),
	}
	tcp := &layers.TCP{
		SrcPort: 40000,
		DstPort: 9,
		Seq:     1,
		Ack:     1,
		ACK:     true,
		Window:  65535,
	}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, eth, ip, tcp))

	return buf.Bytes()
}

// TestCloseWithInflightFrameDoesNotDeadlock pins a shutdown deadlock:
// Stack.Wait waits for the link endpoint while holding the stack lock, and a
// frame still being delivered can need that same lock to answer a stray
// segment with a RST. Engine.Close must therefore wait for the dispatch loop
// to exit before closing the stack. The injector keeps the dispatch loop busy
// delivering exactly such frames while the engine shuts down.
func TestCloseWithInflightFrameDoesNotDeadlock(t *testing.T) {
	frame := strayTCPSegment(t)

	for i := 0; i < 20; i++ {
		h := StartRaw(t, NewConfig().Reject("").Build(t))

		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					h.Source.Inject(frame)
				}
			}
		}()
		// Drain the RST replies so the outbound queue never stalls the stack.
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				case <-h.Source.Outbound():
				}
			}
		}()

		stopped := make(chan struct{})
		go func() {
			h.Stop()
			close(stopped)
		}()

		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			t.Fatal("engine Close deadlocked with a frame delivery in flight")
		}

		close(stop)
		wg.Wait()
	}
}

// TestEngineDoneWhenSourceDies pins the fix for a dead capture going unnoticed:
// the dispatch loop swallowed the read error and the process kept running as a
// silent no-op router. The engine now reports it so main can exit.
func TestEngineDoneWhenSourceDies(t *testing.T) {
	h := StartRaw(t, NewConfig().Reject("").Build(t))

	select {
	case <-h.Engine.Done():
		t.Fatal("the engine must not report a dead capture while the source is alive")
	case <-time.After(100 * time.Millisecond):
	}

	require.NoError(t, h.Source.Close())

	select {
	case <-h.Engine.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("a dead capture must be reported, not swallowed")
	}
}
