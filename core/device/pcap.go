package device

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	"github.com/DaniilSokolyuk/go-pcap2socks/arpr"
	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	"github.com/DaniilSokolyuk/go-pcap2socks/core"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/device/iobased"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/jackpal/gateway"
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
	debugWriter   *pcapgo.Writer
	debugTargetIP net.IP
}

const offset = 0

func Open(pcapCfg cfg.PCAP, captureCfg cfg.Capture, stacker func() Stacker) (_ Device, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("open tun: %v", r)
		}
	}()

	ifce, dev := findDevInterface(pcapCfg.InterfaceGateway)
	slog.Info("Using ethernet interface", "interface", ifce.Name, "name", dev.Name, "mac", ifce.HardwareAddr.String())

	_, network, err := net.ParseCIDR(pcapCfg.Network)
	if err != nil {
		return nil, fmt.Errorf("parse cidr error: %w", err)
	}

	localIP := net.ParseIP(pcapCfg.LocalIP)
	if localIP == nil {
		return nil, fmt.Errorf("parse local ip error: %w", err)
	}

	localIP = localIP.To4()
	if !network.Contains(localIP) {
		return nil, fmt.Errorf("local ip (%s) not in network (%s)", localIP, network)
	}

	var localMAC net.HardwareAddr
	if pcapCfg.LocalMAC != "" {
		localMAC, err = net.ParseMAC(pcapCfg.LocalMAC)
		if localMAC == nil {
			return nil, fmt.Errorf("parse local mac error: %w", err)
		}
	} else {
		localMAC = ifce.HardwareAddr
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
	err = pcaph.SetBPFFilter(fmt.Sprintf("arp or src net %s", network.String()))
	if err != nil {
		return nil, fmt.Errorf("set bpf filter error: %w", err)
	}

	mtu := pcapCfg.MTU
	if mtu == 0 {
		mtu = uint32(ifce.MTU)
	}

	ipRangeStart, ipRangeEnd := calculateIPRange(network, localIP)
	recommendedMTU := calculateRecommendedMTU(mtu)

	// Log network settings in a cleaner format
	slog.Info("Configure your device with these network settings:")
	slog.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	slog.Info(fmt.Sprintf("  IP Address:     %s - %s", ipRangeStart.String(), ipRangeEnd.String()))
	slog.Info(fmt.Sprintf("  Subnet Mask:    %s", net.IP(network.Mask).String()))
	slog.Info(fmt.Sprintf("  Gateway:        %s", localIP.String()))
	slog.Info(fmt.Sprintf("  MTU:            %d (or lower)", recommendedMTU))
	slog.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	t := &PCAP{
		name:       "dspcap",
		stacker:    stacker,
		Interface:  ifce,
		network:    network,
		localIP:    localIP,
		localMAC:   localMAC,
		handle:     pcaph,
		ipMacTable: make(map[string]net.HardwareAddr),
	}

	// Setup PCAP capture if enabled
	if captureCfg.Enabled && captureCfg.TargetIP != "" {
		targetIP := net.ParseIP(captureCfg.TargetIP)
		if targetIP != nil {
			// Convert to IPv4 if needed
			if v4 := targetIP.To4(); v4 != nil {
				targetIP = v4
			}
			t.debugTargetIP = targetIP

			// Create PCAP writer
			outputFile := captureCfg.OutputFile
			if outputFile == "" {
				outputFile = "capture.pcap"
			}

			f, err := os.Create(outputFile)
			if err != nil {
				slog.Error("Failed to create PCAP file", "error", err)
			} else {
				w := pcapgo.NewWriter(f)
				err = w.WriteFileHeader(65536, layers.LinkTypeEthernet)
				if err != nil {
					slog.Error("Failed to write PCAP header", "error", err)
					_ = f.Close()
				} else {
					t.debugWriter = w
					slog.Info("PCAP capture enabled",
						"targetIP", targetIP.String(),
						"outputFile", outputFile)
				}
			}
		}
	}

	ep, err := iobased.New(t, mtu, offset, t.localMAC)
	if err != nil {
		return nil, fmt.Errorf("create endpoint: %w", err)
	}
	t.ep = ep
	// we are in L2 and using ethernet header
	t.Endpoint = ethernet.New(ep)

	// send gratuitous arp
	{
		arpGratuitous, err := arpr.SendGratuitousArp(localIP, localMAC)
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

	// Check if we should capture this packet
	if t.debugWriter != nil && t.debugTargetIP != nil {
		ethProtocol := header.Ethernet(data)
		if ethProtocol.Type() == header.IPv4ProtocolNumber {
			ipProtocol := header.IPv4(data[14:])
			srcAddr := ipProtocol.SourceAddress()
			dstAddr := ipProtocol.DestinationAddress()
			srcIP := srcAddr.AsSlice()
			dstIP := dstAddr.AsSlice()

			// Capture if source or destination matches target IP
			if bytes.Equal(srcIP, t.debugTargetIP) || bytes.Equal(dstIP, t.debugTargetIP) {
				if len(data) > 2000 {
					slog.Warn("Captured packet is larger than 2000 bytes, truncating",
						"length", len(data), "captureInfo", ci)
				}
				err := t.debugWriter.WritePacket(ci, data)
				if err != nil {
					slog.Error("Failed to write packet to PCAP", "error", err)
				}
			}
		}
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

func findDevInterface(cfgIfce string) (net.Interface, pcap.Interface) {
	var targetIface net.IP
	if cfgIfce != "" {
		targetIface = net.ParseIP(cfgIfce)
		if targetIface == nil {
			panic(fmt.Errorf("parse ip error, %s", cfgIfce))
		}
	} else {
		var err error
		targetIface, err = gateway.DiscoverInterface()
		if err != nil {
			panic(fmt.Errorf("discover interface error: %w", err))
		}
	}

	// Get a list of all interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	// Get a list of all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}

	var foundIface net.Interface
	var foundDev pcap.Interface

	for _, iface := range ifaces {
		var addr *net.IPNet

		if addrs, err := iface.Addrs(); err != nil {
			continue
		} else {
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok {
					if ip4 := ipnet.IP.To4(); ip4 != nil && bytes.Equal(ip4, targetIface.To4()) {
						addr = &net.IPNet{
							IP:   ip4,
							Mask: ipnet.Mask[len(ipnet.Mask)-4:],
						}
						break
					}
				}
			}
		}

		if addr == nil {
			continue
		}

		for _, dev := range devices {
			for _, address := range dev.Addresses {
				if address.IP.Equal(addr.IP) {
					foundIface = iface
					foundDev = dev
					break
				}
			}
		}
	}

	return foundIface, foundDev
}

type Stacker interface {
	AddStaticNeighbor(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, linkAddr tcpip.LinkAddress) tcpip.Error
	AddProtocolAddress(id tcpip.NICID, protocolAddress tcpip.ProtocolAddress, properties stack.AddressProperties) tcpip.Error
}

// calculateIPRange calculates the usable IP range for the given network
func calculateIPRange(network *net.IPNet, gatewayIP net.IP) (start, end net.IP) {
	networkIP := network.IP.To4()
	start = make(net.IP, 4)
	end = make(net.IP, 4)

	// Calculate start IP (first usable IP after network address)
	copy(start, networkIP)
	// Increment the last octet by 1 to get first usable IP
	start[3]++

	// Calculate end IP (last usable IP before broadcast)
	for i := 0; i < 4; i++ {
		end[i] = networkIP[i] | ^network.Mask[i]
	}
	end[3]-- // Exclude broadcast address

	// If start IP is the gateway, increment to next IP
	if start.Equal(gatewayIP) {
		start[3]++
	}

	return start, end
}

// calculateRecommendedMTU calculates the recommended MTU based on interface MTU
func calculateRecommendedMTU(interfaceMTU uint32) uint32 {
	const ethernetHeaderSize = 14
	recommendedMTU := interfaceMTU - ethernetHeaderSize
	if recommendedMTU <= 0 {
		recommendedMTU = 1486 // Default safe value
	}
	return recommendedMTU
}
