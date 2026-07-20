package device

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DaniilSokolyuk/go-pcap2socks/arpr"
	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	"github.com/DaniilSokolyuk/go-pcap2socks/core"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/device/iobased"
	localdns "github.com/DaniilSokolyuk/go-pcap2socks/dns"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type PCAP struct {
	stack.LinkEndpoint

	name string

	network    *net.IPNet
	localIP    net.IP
	localMAC   net.HardwareAddr
	handle     *pcap.Handle
	ipMacTable map[string]net.HardwareAddr
	Interface  net.Interface
	mtu        uint32 // Configured MTU (may differ from Interface.MTU)
	rMux       sync.Mutex
	wMux       sync.Mutex // serializes handle.WritePacketData, since gateway-DNS replies can be written concurrently with normal outbound writes
	closed     atomic.Bool
	stacker    func() Stacker

	// dnsCfg holds the DNS servers from config.json, used to answer
	// queries clients send directly to the gateway's own IP. See
	// handleGatewayDNS.
	dnsCfg cfg.DNS
}

const offset = 0

func Open(captureCfg cfg.Capture, dnsCfg cfg.DNS, ifce net.Interface, netConfig *NetworkConfig, stacker func() Stacker) (_ Device, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("open tun: %v", r)
		}
	}()

	// Find the pcap device for this interface
	dev, err := findPcapDevice(ifce)
	if err != nil {
		return nil, err
	}

	pcaphInactive, err := createPcapHandle(dev)
	if err != nil {
		return nil, err
	}

	pcaph, err := pcaphInactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("open live error: %w", err)
	}

	// BPF filter breakdown:
	// 1. ARP packets: (arp dst host <localIP> and arp src net <network> and not arp src host <localIP>)
	//    - Only ARP requests TO us (arp dst host)
	//    - From devices in our network (arp src net)
	//    - Not from ourselves (not arp src host) - loop prevention
	// 2. Gateway-directed DNS: (udp and dst host <localIP> and dst port 53 and src net <network> and not src host <localIP>)
	//    - UDP DNS queries a client sends straight to the gateway's own IP
	//      (used when a device's DNS server is configured to be the gateway
	//      itself). These never reach the gVisor stack or the normal
	//      outbound/routing path - they're answered directly in Read()
	//      using the servers from config.json (see handleGatewayDNS).
	//      Deliberately narrow (UDP/53 only) so nothing else about how
	//      traffic to/through the gateway is captured changes.
	// 3. IPv4 packets: (src net <network> and not dst net <network> and not (icmp and src host <localIP>))
	//    - All IPv4 packets from the configured network
	//    - Not destined to the local network (only capture internet-bound traffic)
	//    - Exclude ICMP from ourselves (loop prevention in promiscuous mode)
	//
	// ARP field access in BPF:
	// - "arp src host X" / "arp src net X" - checks Source Protocol Address (SPA) field
	// - "arp dst host X" / "arp dst net X" - checks Target Protocol Address (TPA) field
	bpfFilter := fmt.Sprintf(
		"(arp dst host %s and arp src net %s and not arp src host %s) or (udp and dst host %s and dst port 53 and src net %s and not src host %s) or (src net %s and not dst net %s and not (icmp and src host %s))",
		netConfig.LocalIP.String(),
		netConfig.Network.String(),
		netConfig.LocalIP.String(),
		netConfig.LocalIP.String(),
		netConfig.Network.String(),
		netConfig.LocalIP.String(),
		netConfig.Network.String(),
		netConfig.Network.String(),
		netConfig.LocalIP.String(),
	)
	err = pcaph.SetBPFFilter(bpfFilter)
	if err != nil {
		return nil, fmt.Errorf("set bpf filter error: %w", err)
	}

	t := &PCAP{
		name:       "dspcap",
		stacker:    stacker,
		Interface:  ifce,
		network:    netConfig.Network,
		localIP:    netConfig.LocalIP,
		localMAC:   netConfig.LocalMAC,
		mtu:        netConfig.MTU,
		handle:     pcaph,
		ipMacTable: make(map[string]net.HardwareAddr),
		dnsCfg:     dnsCfg,
	}

	ep, err := iobased.New(t, netConfig.MTU, offset, t.localMAC)
	if err != nil {
		return nil, fmt.Errorf("create endpoint: %w", err)
	}

	// we are in L2 and using ethernet header
	t.LinkEndpoint = ethernet.New(ep)

	// Setup PCAP capture if enabled
	if captureCfg.Enabled {
		snifferEp, err := NewEthSniffer(t.LinkEndpoint, captureCfg.OutputFile)
		if err != nil {
			slog.Error("Failed to setup PCAP capture", "error", err)
		} else {
			t.LinkEndpoint = snifferEp
		}
	}

	// send gratuitous arp
	{
		arpGratuitous, err := arpr.SendGratuitousArp(netConfig.LocalIP, netConfig.LocalMAC)
		if err != nil {
			return nil, fmt.Errorf("send gratuitous arp error: %w", err)
		}

		err = t.handle.WritePacketData(arpGratuitous)
		if err != nil {
			return nil, fmt.Errorf("write packet error: %w", err)
		}
	}

	return t, nil
}

func createPcapHandle(dev pcap.Interface) (*pcap.InactiveHandle, error) {
	handle, err := pcap.NewInactiveHandle(dev.Name)
	if err != nil {
		return nil, fmt.Errorf("new inactive handle error: %w", err)
	}

	err = handle.SetPromisc(true)
	if err != nil {
		return nil, fmt.Errorf("set promisc error: %w", err)
	}

	err = handle.SetSnapLen(1600)
	if err != nil {
		return nil, fmt.Errorf("set snap len error: %w", err)
	}

	// Balanced mode: a small poll timeout instead of immediate mode.
	// This lets the kernel batch packets under load (higher throughput,
	// fewer syscalls/wakeups) while adding at most ~4ms of latency in
	// the worst case, which is imperceptible for gaming.
	// It also allows the read loop to periodically wake up and notice
	// that the device was closed (safe shutdown / hot reload).
	err = handle.SetTimeout(4 * time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("set timeout error: %w", err)
	}

	err = handle.SetBufferSize(32 * 1024 * 1024)
	if err != nil {
		return nil, fmt.Errorf("set buffer size error: %w", err)
	}

	return handle, nil
}

func (t *PCAP) Read() ([]byte, error) {
	t.rMux.Lock()
	defer t.rMux.Unlock()

	for {
		if t.closed.Load() {
			return nil, net.ErrClosed
		}

		data, _, err := t.handle.ZeroCopyReadPacketData()
		if err != nil {
			// Timeout is not fatal - it just means no packets arrived
			// within the poll interval. Keep waiting.
			if errors.Is(err, pcap.NextErrorTimeoutExpired) {
				continue
			}
			return nil, fmt.Errorf("pcap read: %w", err)
		}

		ethProtocol := header.Ethernet(data)
		switch ethProtocol.Type() {
		case header.IPv4ProtocolNumber:
			ipProtocol := header.IPv4(data[14:])
			srcAddress := ipProtocol.SourceAddress()
			if !t.network.Contains(srcAddress.AsSlice()) {
				continue
			}

			if !bytes.Equal(srcAddress.AsSlice(), t.localIP) {
				t.SetHardwareAddr(srcAddress.AsSlice(), []byte(ethProtocol.SourceAddress()))
			}

			// DNS queries sent straight to the gateway's own IP (client's
			// DNS server configured as the gateway) are answered here
			// directly - they never reach the gVisor stack, so nothing
			// about how other traffic is routed changes.
			dstAddress := ipProtocol.DestinationAddress()
			if bytes.Equal(dstAddress.AsSlice(), t.localIP) {
				if t.handleGatewayDNS(data) {
					continue
				}
			}
		case header.ARPProtocolNumber:
			gPckt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
			arpLayer, isArp := gPckt.Layer(layers.LayerTypeARP).(*layers.ARP)
			if !isArp {
				continue
			}

			srcIP := net.IP(arpLayer.SourceProtAddress)
			dstIP := net.IP(arpLayer.DstProtAddress)

			// Same like in BPF filter
			if !bytes.Equal(srcIP, t.localIP) &&
				bytes.Equal(dstIP, t.localIP) &&
				t.network.Contains(srcIP) {
				t.SetHardwareAddr(srcIP, arpLayer.SourceHwAddress)
			} else {
				continue
			}

		default:
			continue
		}

		// IMPORTANT: ZeroCopyReadPacketData returns a slice that is only
		// valid until the next read call. gVisor may hold the packet longer
		// (TCP reassembly, out-of-order queues), so we MUST copy it here.
		// Not copying causes silent packet corruption, checksum errors,
		// retransmits and unstable throughput.
		pkt := make([]byte, len(data))
		copy(pkt, data)
		return pkt, nil
	}
}

func (t *PCAP) Write(p []byte) (n int, err error) {
	t.wMux.Lock()
	err = t.handle.WritePacketData(p)
	t.wMux.Unlock()
	if err != nil {
		// Propagate the error instead of silently dropping the packet,
		// so upper layers know the write failed.
		return 0, fmt.Errorf("pcap write: %w", err)
	}

	return len(p), nil
}

func (t *PCAP) Name() string {
	return t.name
}

func (t *PCAP) Close() {
	if t.closed.Swap(true) {
		return // already closed
	}

	// Wait for any in-flight read to finish before closing the pcap
	// handle: closing it while another goroutine is inside
	// ZeroCopyReadPacketData is a data race that can crash the process.
	// The read loop wakes up at least every poll timeout (~4ms) and
	// exits once it sees the closed flag.
	t.rMux.Lock()
	t.handle.Close()
	t.rMux.Unlock()

	t.LinkEndpoint.Close() // Cascade close: sniffer → ethernet → iobased
}

func (t *PCAP) Type() string {
	return "pcap"
}

func (t *PCAP) SetHardwareAddr(srcIP net.IP, srcMAC net.HardwareAddr) {
	if _, ok := t.ipMacTable[string(srcIP)]; !ok {
		slog.Info(fmt.Sprintf("Device %s (%s) joined the network", srcIP, srcMAC))
		// Copy IP and MAC: the incoming slices may reference the pcap
		// read buffer, which is reused on the next read.
		srcIP = append(net.IP(nil), srcIP...)
		srcMAC = append(net.HardwareAddr(nil), srcMAC...)
		t.ipMacTable[string(srcIP)] = srcMAC
		// after restart app some devices doesnt react to GratuitousArp, so we need to add them manually
		t.stacker().AddStaticNeighbor(core.NicID, header.IPv4ProtocolNumber, tcpip.AddrFrom4Slice(srcIP), tcpip.LinkAddress(srcMAC))
	}
}

// handleGatewayDNS answers a UDP DNS query addressed directly to the
// gateway's own IP (client's DNS server set to the gateway) using the
// servers configured in config.json - the same servers the "dns-out"
// outbound would use for normally-routed DNS traffic. Returns true if data
// was a DNS query and has been handled (queued for an async reply); the
// caller should not forward the packet into the gVisor stack in that case.
//
// This is deliberately self-contained: it never touches gVisor, routing
// rules, or the normal internet-bound capture path, so it can't affect any
// other traffic.
func (t *PCAP) handleGatewayDNS(data []byte) bool {
	ip := header.IPv4(data[14:])
	if ip.TransportProtocol() != header.UDPProtocolNumber {
		return false
	}

	ihl := int(ip.HeaderLength())
	udpStart := 14 + ihl
	if ihl < header.IPv4MinimumSize || len(data) < udpStart+header.UDPMinimumSize {
		return false
	}

	udp := header.UDP(data[udpStart:])
	if udp.DestinationPort() != 53 {
		return false
	}

	payload := data[udpStart+header.UDPMinimumSize:]
	if len(payload) == 0 {
		return false
	}

	query := new(dns.Msg)
	if err := query.Unpack(payload); err != nil {
		// Not a well-formed DNS message - let it fall through to the
		// normal path rather than silently swallowing it.
		return false
	}

	// Copy everything needed before the pcap read buffer is reused by the
	// next ZeroCopyReadPacketData call.
	eth := header.Ethernet(data)
	srcAddress := ip.SourceAddress()
	clientMAC := append(net.HardwareAddr(nil), []byte(eth.SourceAddress())...)
	clientIP := append(net.IP(nil), srcAddress.AsSlice()...)
	clientPort := udp.SourcePort()

	go t.answerGatewayDNS(query, clientMAC, clientIP, clientPort)

	return true
}

func (t *PCAP) answerGatewayDNS(query *dns.Msg, clientMAC net.HardwareAddr, clientIP net.IP, clientPort uint16) {
	response, err := t.exchangeDNS(query)
	if err != nil {
		slog.Error("gateway dns exchange failed", slog.Any("err", err))
		return
	}

	packed, err := response.Pack()
	if err != nil {
		slog.Error("gateway dns pack response failed", slog.Any("err", err))
		return
	}

	reply, err := buildDNSReply(t.localIP, t.localMAC, clientIP, clientMAC, clientPort, packed)
	if err != nil {
		slog.Error("gateway dns build reply failed", slog.Any("err", err))
		return
	}

	if _, err := t.Write(reply); err != nil {
		slog.Error("gateway dns write reply failed", slog.Any("err", err))
	}
}

// exchangeDNS resolves query using the servers from config.json, in order,
// the same way proxy.DNS (the "dns-out" outbound) does for normally-routed
// DNS traffic - so behavior is identical either way DNS reaches this app.
func (t *PCAP) exchangeDNS(query *dns.Msg) (*dns.Msg, error) {
	client := &dns.Client{Timeout: 5 * time.Second, UDPSize: dns.DefaultMsgSize}

	var lastErr error
	for _, server := range t.dnsCfg.Servers {
		var response *dns.Msg
		var err error

		if server.Address == "local" {
			response, err = localdns.NewLocalClient(t.Interface.Name).Exchange(query)
		} else {
			response, _, err = client.Exchange(query, server.Address)
		}

		if err == nil {
			return response, nil
		}
		lastErr = err
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no dns servers configured")
	}
	return nil, lastErr
}

// buildDNSReply crafts a raw Ethernet+IPv4+UDP frame carrying a packed DNS
// response, addressed back to the client that asked.
func buildDNSReply(srcIP net.IP, srcMAC net.HardwareAddr, dstIP net.IP, dstMAC net.HardwareAddr, dstPort uint16, payload []byte) ([]byte, error) {
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	udpLayer := &layers.UDP{
		SrcPort: 53,
		DstPort: layers.UDPPort(dstPort),
	}
	if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return nil, err
	}

	sbuf := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(sbuf, options, ethernetLayer, ipLayer, udpLayer, gopacket.Payload(payload)); err != nil {
		return nil, err
	}

	return sbuf.Bytes(), nil
}

type Stacker interface {
	AddStaticNeighbor(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, linkAddr tcpip.LinkAddress) tcpip.Error
	AddProtocolAddress(id tcpip.NICID, protocolAddress tcpip.ProtocolAddress, properties stack.AddressProperties) tcpip.Error
}

func findPcapDevice(ifce net.Interface) (pcap.Interface, error) {
	// Get all pcap devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return pcap.Interface{}, fmt.Errorf("find all devices error: %w", err)
	}

	// Get interface addresses
	addrs, err := ifce.Addrs()
	if err != nil {
		return pcap.Interface{}, fmt.Errorf("get interface addresses error: %w", err)
	}

	// Find matching device
	for _, dev := range devices {
		for _, devAddr := range dev.Addresses {
			for _, ifaceAddr := range addrs {
				if ipnet, ok := ifaceAddr.(*net.IPNet); ok {
					if devAddr.IP.Equal(ipnet.IP) {
						return dev, nil
					}
				}
			}
		}
	}

	return pcap.Interface{}, fmt.Errorf("pcap device not found for interface %s", ifce.Name)
}
