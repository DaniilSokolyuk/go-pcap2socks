package main

import (
	"bytes"
	"fmt"
	"github.com/DaniilSokolyuk/go-pcap2socks/arpr"
	"github.com/DaniilSokolyuk/go-pcap2socks/core"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/device"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/option"
	"github.com/DaniilSokolyuk/go-pcap2socks/proxy"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func main() {
	err := run()
	if err != nil {
		slog.Error("run error: %w", err)
	}

	quitChannel := make(chan os.Signal)
	signal.Notify(quitChannel, syscall.SIGINT, syscall.SIGTERM)
	<-quitChannel
}

func run() error {
	ifce, dev := findDevInterface()

	var err error
	_defaultProxy, err = proxy.NewSocks5("127.0.0.1:1080", "", "")
	if err != nil {
		return fmt.Errorf("new socks5 error: %w", err)

	}
	proxy.SetDialer(_defaultProxy)

	pcaph, err := pcap.OpenLive(dev.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open live error: %w", err)
	}

	network := net.IPNet{
		IP:   net.ParseIP("172.24.2.1"),
		Mask: net.CIDRMask(24, 32),
	}

	engine := &Engine{
		Name:         "pcap/" + ifce.Name,
		Interface:    ifce,
		LocalNetwork: network,
		LocalIP:      network.IP.To4(),
		LocalMAC:     net.HardwareAddr{0xde, 0xad, 0xbe, 0xee, 0xee, 0xef},
		handle:       pcaph,
		ipMacTable:   make(map[string]net.HardwareAddr),
	}

	ll := network.IP.To4().String()
	fmt.Println(ll)

	go func() {
		//sleep for 1 second to wait for the stack to be ready
		reply, err := arpr.SendGratuitousArp(engine.LocalIP, engine.LocalMAC)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = pcaph.WritePacketData(reply)
		if err != nil {
			fmt.Println(err)
		}
	}()

	_defaultDevice, err = device.Open(engine.Name, uint32(engine.Interface.MTU), engine, engine.LocalMAC)
	if err != nil {
		return err
	}

	if _defaultStack, err = core.CreateStack(&core.Config{
		LinkEndpoint:     _defaultDevice,
		TransportHandler: &core.Tunnel{},
		MulticastGroups:  []net.IP{},
		Options:          []option.Option{},
	}); err != nil {
		slog.Error("create stack error: %w", err)
	}

	return nil
}

var (
	_engineMu sync.Mutex

	// _defaultProxy holds the default proxy for the engine.
	_defaultProxy proxy.Proxy

	// _defaultDevice holds the default device for the engine.
	_defaultDevice device.Device

	// _defaultStack holds the default stack for the engine.
	_defaultStack *stack.Stack
)

type Engine struct {
	LocalNetwork net.IPNet
	LocalIP      net.IP
	LocalMAC     net.HardwareAddr
	handle       *pcap.Handle
	readCh       chan []byte
	ipMacTable   map[string]net.HardwareAddr
	Interface    net.Interface
	Name         string
}

func (c Engine) Read(dst []byte) (n int, err error) {
	data, _, err := c.handle.ZeroCopyReadPacketData()
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
		if !c.LocalNetwork.Contains(srcAddress.AsSlice()) {
			return 0, nil
		}
		c.SetHardwareAddr(srcAddress.AsSlice(), []byte(ethProtocol.SourceAddress()))
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
		if bytes.Compare(srcIP, c.LocalIP) != 0 &&
			bytes.Compare(dstIP, c.LocalIP) == 0 &&
			c.LocalNetwork.Contains(srcIP) {
			c.SetHardwareAddr(srcIP, arpLayer.SourceHwAddress)
		} else {
			return 0, nil
		}

	default:
		return 0, nil
	}

	copy(dst, data)
	return len(data), nil
}

func (c Engine) Write(p []byte) (n int, err error) {
	err = c.handle.WritePacketData(p)
	if err != nil {
		slog.Error("write packet error: %w", err)
		return 0, nil
	}

	//fmt.Println("==============================reply: " + gopacket.NewPacket(p, layers.LayerTypeEthernet, gopacket.Default).String())
	return len(p), nil
}

func (c Engine) Close() error {
	c.handle.Close()
	return nil
}

func (c Engine) SetHardwareAddr(srcIP net.IP, srcMAC net.HardwareAddr) {
	if _, ok := c.ipMacTable[string(srcIP)]; !ok {
		slog.Info(fmt.Sprintf("Device %s (%s) joined the network", srcIP, srcMAC))
		c.ipMacTable[string(srcIP)] = srcMAC
		// after restart app some devices doesnt react to GratuitousArp, so we need to add them manually
		_defaultStack.AddStaticNeighbor(core.NicID, header.IPv4ProtocolNumber, tcpip.AddrFrom4Slice(srcIP), tcpip.LinkAddress(srcMAC))
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
