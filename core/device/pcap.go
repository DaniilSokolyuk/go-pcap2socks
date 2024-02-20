package device

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	"github.com/DaniilSokolyuk/go-pcap2socks/core"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/device/iobased"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
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
}

const offset = 0

func Open(cfg cfg.PCAP, stacker func() Stacker) (_ Device, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("open tun: %v", r)
		}
	}()

	ifce, dev := findDevInterface(cfg.InterfaceGateway)
	slog.Info("Using ethernet interface", "interface", ifce.Name, "name", dev.Name)

	_, network, err := net.ParseCIDR(cfg.Network)
	if err != nil {
		return nil, fmt.Errorf("parse cidr error: %w", err)
	}

	localIP := net.ParseIP(cfg.LocalIP)
	if localIP == nil {
		return nil, fmt.Errorf("parse local ip error: %w", err)
	}

	localIP = localIP.To4()
	if !network.Contains(localIP) {
		return nil, fmt.Errorf("local ip (%s) not in network (%s)", localIP, network)
	}

	localMAC, err := net.ParseMAC(cfg.LocalMAC)
	if localMAC == nil {
		return nil, fmt.Errorf("parse local mac error: %w", err)
	}

	slog.Default().Info("Enter this settings in your device's network settings",
		"ip", network.String(),
		"mask", net.IP(network.Mask).String(),
		"gateway", localIP.String())

	pcaph, err := pcap.OpenLive(dev.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open live error: %w", err)
	}

	//arp or src net 172.24.2.0/24 or ether dst de:ad:be:ee:ee:ef
	err = pcaph.SetBPFFilter(fmt.Sprintf("arp or src net %s or ether dst %s", network.String(), localMAC.String()))
	if err != nil {
		return nil, fmt.Errorf("set bpf filter error: %w", err)
	}

	mtu := cfg.MTU
	if mtu == 0 {
		mtu = uint32(ifce.MTU)
	}

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

	ep, err := iobased.New(t, mtu, offset, t.localMAC)
	if err != nil {
		return nil, fmt.Errorf("create endpoint: %w", err)
	}
	t.ep = ep
	// we are in L2 and using ethernet header
	t.Endpoint = ethernet.New(ep)

	return t, nil
}

func (t *PCAP) Read() []byte {
	t.rMux.Lock()
	defer t.rMux.Unlock()
	data, _, err := t.handle.ZeroCopyReadPacketData()
	if err != nil {
		slog.Error("read packet error: %w", err)
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
		slog.Error("write packet error: %w", err)
		return 0, nil
	}

	//fmt.Println("==============================reply: " + gopacket.NewPacket(p, layers.LayerTypeEthernet, gopacket.Default).String())
	return len(p), nil
}

func (t *PCAP) Name() string {
	return t.name
}

func (t *PCAP) Close() error {
	defer t.ep.Close()
	t.handle.Close()
	return nil
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
}
