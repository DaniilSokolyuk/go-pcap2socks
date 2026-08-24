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
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// ethDevice is an ethernet device on top of a FrameSource. It filters inbound
// frames to the configured network and learns the MAC address of every device
// it sees, feeding the stack's neighbor cache.
type ethDevice struct {
	stack.LinkEndpoint

	name string
	typ  string

	network    *net.IPNet
	localIP    net.IP
	localMAC   net.HardwareAddr
	src        FrameSource
	ipMacTable map[string]net.HardwareAddr
	mtu        uint32 // Configured MTU (may differ from Interface.MTU)
	rMux       sync.Mutex
	stacker    func() Stacker
}

var _ Device = (*ethDevice)(nil)

const offset = 0

// Open captures on the given interface with a live pcap handle.
func Open(captureCfg cfg.Capture, ifce net.Interface, netConfig *NetworkConfig, stacker func() Stacker) (_ Device, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("open pcap: %v", r)
		}
	}()

	src, err := newPcapSource(ifce, netConfig)
	if err != nil {
		return nil, err
	}

	dev, err := OpenWithSource(captureCfg, src, "pcap", netConfig, stacker)
	if err != nil {
		_ = src.Close()
		return nil, err
	}

	return dev, nil
}

// OpenWithSource builds a device on top of an arbitrary frame source. It is the
// shared body of Open and the entry point used by tests, which pass a
// MemSource instead of a pcap handle.
func OpenWithSource(captureCfg cfg.Capture, src FrameSource, typ string, netConfig *NetworkConfig, stacker func() Stacker) (Device, error) {
	t := &ethDevice{
		name:       "dspcap",
		typ:        typ,
		stacker:    stacker,
		network:    netConfig.Network,
		localIP:    netConfig.LocalIP,
		localMAC:   netConfig.LocalMAC,
		mtu:        netConfig.MTU,
		src:        src,
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

		err = src.WriteFrame(arpGratuitous)
		if err != nil {
			return nil, fmt.Errorf("write packet error: %w", err)
		}
	}

	return t, nil
}

// Read returns the next frame that belongs to the configured network, or nil
// when the frame should be dropped. It also learns the sender's MAC address.
func (t *ethDevice) Read() ([]byte, error) {
	t.rMux.Lock()
	defer t.rMux.Unlock()

	data, err := t.src.ReadFrame()
	if err != nil {
		return nil, err
	}

	ethProtocol := header.Ethernet(data)
	switch ethProtocol.Type() {
	case header.IPv4ProtocolNumber:
		if len(data) < header.EthernetMinimumSize+header.IPv4MinimumSize {
			return nil, nil
		}

		ipProtocol := header.IPv4(data[header.EthernetMinimumSize:])
		srcAddress := ipProtocol.SourceAddress()
		if !t.network.Contains(srcAddress.AsSlice()) {
			return nil, nil
		}

		if !bytes.Equal(srcAddress.AsSlice(), t.localIP.To4()) {
			t.SetHardwareAddr(srcAddress.AsSlice(), []byte(ethProtocol.SourceAddress()))
		}
	case header.ARPProtocolNumber:
		gPckt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		arpLayer, isArp := gPckt.Layer(layers.LayerTypeARP).(*layers.ARP)
		if !isArp {
			return nil, nil
		}

		srcIP := net.IP(arpLayer.SourceProtAddress)
		dstIP := net.IP(arpLayer.DstProtAddress)

		// Same like in BPF filter
		if !srcIP.Equal(t.localIP) && dstIP.Equal(t.localIP) && t.network.Contains(srcIP) {
			t.SetHardwareAddr(srcIP, arpLayer.SourceHwAddress)
		} else {
			return nil, nil
		}

	default:
		return nil, nil
	}

	return data, nil
}

func (t *ethDevice) Write(p []byte) (n int, err error) {
	err = t.src.WriteFrame(p)
	if err != nil {
		slog.Error("write packet error", slog.Any("err", err))
		return 0, nil
	}

	return len(p), nil
}

func (t *ethDevice) Name() string {
	return t.name
}

func (t *ethDevice) Close() {
	_ = t.src.Close()
	t.LinkEndpoint.Close() // Cascade close: sniffer → ethernet → iobased
}

func (t *ethDevice) Type() string {
	return t.typ
}

func (t *ethDevice) SetHardwareAddr(srcIP net.IP, srcMAC net.HardwareAddr) {
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
