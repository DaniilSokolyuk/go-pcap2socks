package device

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/DaniilSokolyuk/go-pcap2socks/arpr"
	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	"github.com/DaniilSokolyuk/go-pcap2socks/core"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/device/iobased"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
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
	stacker    func() Stacker
}

const offset = 0

func Open(captureCfg cfg.Capture, ifce net.Interface, netConfig *NetworkConfig, stacker func() Stacker) (_ Device, err error) {
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
	// 2. IPv4 packets: (src net <network> and not dst net <network> and not (icmp and src host <localIP>))
	//    - All IPv4 packets from the configured network
	//    - Not destined to the local network (only capture internet-bound traffic)
	//    - Exclude ICMP from ourselves (loop prevention in promiscuous mode)
	//
	// ARP field access in BPF:
	// - "arp src host X" / "arp src net X" - checks Source Protocol Address (SPA) field
	// - "arp dst host X" / "arp dst net X" - checks Target Protocol Address (TPA) field
	bpfFilter := fmt.Sprintf(
		"(arp dst host %s and arp src net %s and not arp src host %s) or (src net %s and not dst net %s and not (icmp and src host %s))",
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

	err = handle.SetTimeout(pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("set timeout error: %w", err)
	}

	err = handle.SetImmediateMode(true)
	if err != nil {
		return nil, fmt.Errorf("set immediate mode error: %w", err)
	}

	err = handle.SetBufferSize(512 * 1024)
	if err != nil {
		return nil, fmt.Errorf("set buffer size error: %w", err)
	}

	return handle, nil
}

func (t *PCAP) Read() []byte {
	t.rMux.Lock()
	defer t.rMux.Unlock()
	data, _, err := t.handle.ZeroCopyReadPacketData()
	if err != nil {
		slog.Error("read packet error: %w", slog.Any("err", err))
		return nil
	}

	ethProtocol := header.Ethernet(data)
	switch ethProtocol.Type() {
	case header.IPv4ProtocolNumber:
		ipProtocol := header.IPv4(data[14:])
		srcAddress := ipProtocol.SourceAddress()
		if !t.network.Contains(srcAddress.AsSlice()) {
			return nil
		}

		if bytes.Compare(srcAddress.AsSlice(), t.localIP) != 0 {
			t.SetHardwareAddr(srcAddress.AsSlice(), []byte(ethProtocol.SourceAddress()))
		}
	case header.ARPProtocolNumber:
		gPckt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		arpLayer, isArp := gPckt.Layer(layers.LayerTypeARP).(*layers.ARP)
		if !isArp {
			return nil
		}

		srcIP := net.IP(arpLayer.SourceProtAddress)
		dstIP := net.IP(arpLayer.DstProtAddress)

		// Same like in BPF filter
		if bytes.Compare(srcIP, t.localIP) != 0 &&
			bytes.Compare(dstIP, t.localIP) == 0 &&
			t.network.Contains(srcIP) {
			t.SetHardwareAddr(srcIP, arpLayer.SourceHwAddress)
		} else {
			return nil
		}

	default:
		return nil
	}

	return data
}

func (t *PCAP) Write(p []byte) (n int, err error) {
	err = t.handle.WritePacketData(p)
	if err != nil {
		slog.Error("write packet error: %w", slog.Any("err", err))
		return 0, nil
	}

	return len(p), nil
}

func (t *PCAP) Name() string {
	return t.name
}

func (t *PCAP) Close() {
	t.handle.Close()
	t.LinkEndpoint.Close() // Cascade close: sniffer → ethernet → iobased
}

func (t *PCAP) Type() string {
	return "pcap"
}

func (t *PCAP) SetHardwareAddr(srcIP net.IP, srcMAC net.HardwareAddr) {
	if _, ok := t.ipMacTable[string(srcIP)]; !ok {
		slog.Info(fmt.Sprintf("Device %s (%s) joined the network", srcIP, srcMAC))
		t.ipMacTable[string(srcIP)] = srcMAC
		// after restart app some devices doesnt react to GratuitousArp, so we need to add them manually
		t.stacker().AddStaticNeighbor(core.NicID, header.IPv4ProtocolNumber, tcpip.AddrFrom4Slice(srcIP), tcpip.LinkAddress(srcMAC))
	}
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
