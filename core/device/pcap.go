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
	*ethernet.Endpoint

	name string
	ep   *iobased.Endpoint

	network    *net.IPNet
	localIP    net.IP
	localMAC   net.HardwareAddr
	handle     *pcap.Handle
	ipMacTable map[string]net.HardwareAddr
	Interface  net.Interface
	rMux       sync.Mutex
	stacker    func() Stacker

	// Debug PCAP capture
	debugCapture *DebugCapture
}

const offset = 0

func Open(pcapCfg cfg.PCAP, captureCfg cfg.Capture, ifce net.Interface, netConfig *NetworkConfig, stacker func() Stacker) (_ Device, err error) {
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

	//arp or src net 172.24.2.0/24
	err = pcaph.SetBPFFilter(fmt.Sprintf("arp or src net %s", netConfig.Network.String()))
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
		handle:     pcaph,
		ipMacTable: make(map[string]net.HardwareAddr),
	}

	// Setup PCAP capture if enabled
	if captureCfg.Enabled && captureCfg.TargetIP != "" {
		debugCapture, err := NewDebugCapture(captureCfg.TargetIP, captureCfg.OutputFile)
		if err != nil {
			slog.Error("Failed to setup PCAP capture", "error", err)
		} else {
			t.debugCapture = debugCapture
		}
	}

	ep, err := iobased.New(t, netConfig.MTU, offset, t.localMAC)
	if err != nil {
		return nil, fmt.Errorf("create endpoint: %w", err)
	}
	t.ep = ep
	// we are in L2 and using ethernet header
	t.Endpoint = ethernet.New(ep)

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
	data, ci, err := t.handle.ZeroCopyReadPacketData()
	if err != nil {
		slog.Error("read packet error: %w", slog.Any("err", err))
		return nil
	}

	// Debug: Parse and log incoming packet
	if slog.Default().Enabled(nil, slog.LevelDebug) && len(data) > 14 {
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		slog.Debug("READ packet", "packet", packet.String())
	}

	// Capture packet if debug is enabled
	if t.debugCapture != nil {
		t.debugCapture.CapturePacket(data, ci)
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
		// //gvisor handle arp requests, but we should filter out arp requests from the expected network
		// cant use gvisor check due spoofing
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
	// Capture outgoing packet if debug is enabled
	if t.debugCapture != nil {
		t.debugCapture.CaptureOutgoingPacket(p)
	}

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
	defer t.ep.Close()
	t.handle.Close()

	// Close debug capture if enabled
	if t.debugCapture != nil {
		t.debugCapture.Close()
	}
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
