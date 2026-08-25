package device

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/DaniilSokolyuk/go-pcap2socks/arpr"
	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
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
	ep         *iobased.Endpoint
	ipMacTable map[string]net.HardwareAddr
	mtu        uint32 // Configured MTU (may differ from Interface.MTU)
	rMux       sync.Mutex

	// neighbors and nicID are set by AttachNeighborCache before the NIC is
	// created, and the NIC is what starts the dispatch loop. Nothing reads them
	// before that happens, so they need no synchronisation.
	neighbors NeighborCache
	nicID     tcpip.NICID
}

var _ Device = (*ethDevice)(nil)

const offset = 0

// Open captures on the given interface with a live pcap handle.
func Open(captureCfg cfg.Capture, ifce net.Interface, netConfig *NetworkConfig) (_ Device, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("open pcap: %v", r)
		}
	}()

	src, err := newPcapSource(ifce, netConfig)
	if err != nil {
		return nil, err
	}

	dev, err := OpenWithSource(captureCfg, src, "pcap", netConfig)
	if err != nil {
		_ = src.Close()
		return nil, err
	}

	return dev, nil
}

// OpenWithSource builds a device on top of an arbitrary frame source. It is the
// shared body of Open and the entry point used by tests, which pass a
// MemSource instead of a pcap handle.
func OpenWithSource(captureCfg cfg.Capture, src FrameSource, typ string, netConfig *NetworkConfig) (Device, error) {
	t := &ethDevice{
		name:       "dspcap",
		typ:        typ,
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

	t.ep = ep

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

	// Nothing below this length has an ethertype to read, and header.Ethernet
	// indexes into the slice without checking.
	if len(data) < header.EthernetMinimumSize {
		return nil, nil
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

		// The address sizes come straight off the wire. Only IPv4 over ethernet
		// is ours to learn from, and the checks below would happily accept an
		// IPv4 mapped 16 byte address that the neighbor cache then panics on.
		if len(arpLayer.SourceProtAddress) != 4 ||
			len(arpLayer.DstProtAddress) != 4 ||
			len(arpLayer.SourceHwAddress) != 6 {
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

// Done is closed when the device stops reading frames, either because it was
// closed or because the frame source failed.
func (t *ethDevice) Done() <-chan struct{} {
	return t.ep.Done()
}

// AttachNeighborCache tells the device where to record the addresses it learns.
// It must be called before the stack creates its NIC, because that is what
// starts the dispatch loop.
func (t *ethDevice) AttachNeighborCache(nc NeighborCache, nicID tcpip.NICID) {
	t.neighbors = nc
	t.nicID = nicID
}

func (t *ethDevice) SetHardwareAddr(srcIP net.IP, srcMAC net.HardwareAddr) {
	if _, ok := t.ipMacTable[string(srcIP)]; ok {
		return
	}
	if t.neighbors == nil {
		return
	}

	slog.Info(fmt.Sprintf("Device %s (%s) joined the network", srcIP, srcMAC))
	t.ipMacTable[string(srcIP)] = srcMAC
	// after restart app some devices doesnt react to GratuitousArp, so we need to add them manually
	t.neighbors.AddStaticNeighbor(t.nicID, header.IPv4ProtocolNumber, tcpip.AddrFrom4Slice(srcIP), tcpip.LinkAddress(srcMAC))
}

// NeighborCache is all the device needs from the stack: somewhere to record the
// MAC address it just learned for an IP. *stack.Stack satisfies it.
type NeighborCache interface {
	AddStaticNeighbor(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, linkAddr tcpip.LinkAddress) tcpip.Error
}
