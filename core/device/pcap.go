package device

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"sync"

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

func Open(name string, cidr string, mtu uint32, stacker func() Stacker) (_ Device, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("open tun: %v", r)
		}
	}()

	ifce, dev := findDevInterface()

	pcaph, err := pcap.OpenLive(dev.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open live error: %w", err)
	}

	localIP, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse cidr error: %w", err)
	}

	if mtu == 0 {
		mtu = uint32(ifce.MTU)
	}

	t := &PCAP{
		stacker:    stacker,
		name:       name,
		Interface:  ifce,
		network:    network,
		localIP:    localIP.To4(),
		localMAC:   net.HardwareAddr{0xde, 0xad, 0xbe, 0xee, 0xee, 0xef},
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

func (t *PCAP) Read(dst []byte) (n int, err error) {
	t.rMux.Lock()
	defer t.rMux.Unlock()
	data, _, err := t.handle.ZeroCopyReadPacketData()
	if err != nil {
		slog.Error("read packet error: %w", err)
		return 0, nil
	}

	ethProtocol := header.Ethernet(data)
	switch ethProtocol.Type() {
	case header.IPv4ProtocolNumber:
		//fmt.Println("==============================reply: " + gopacket.NewPacket(p, layers.LayerTypeEthernet, gopacket.Default).String())
		ipProtocol := header.IPv4(data[14:])
		srcAddress := ipProtocol.SourceAddress()
		if !t.network.Contains(srcAddress.AsSlice()) {
			return 0, nil
		}
		t.SetHardwareAddr(srcAddress.AsSlice(), []byte(ethProtocol.SourceAddress()))
	case header.ARPProtocolNumber:
		gPckt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		arpLayer, isArp := gPckt.Layer(layers.LayerTypeARP).(*layers.ARP)
		if !isArp {
			return 0, nil
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
			return 0, nil
		}

	default:
		return 0, nil
	}

	copy(dst, data)
	return len(data), nil
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

func findDevInterface() (net.Interface, pcap.Interface) {
	gateway, err := gateway.DiscoverInterface()
	if err != nil {
		panic(err)
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
					if ip4 := ipnet.IP.To4(); ip4 != nil && bytes.Equal(ip4, gateway.To4()) {
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
