package main

import (
	"bytes"
	"fmt"
	"net"

	"github.com/DaniilSokolyuk/go-pcap2socks/arp"
	"github.com/DaniilSokolyuk/go-pcap2socks/netstack"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	run()
}

func run() error {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("find device error: %w", err)
	}

	pcaph, err := pcap.OpenLive(interfaces[0].Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open live error: %w", err)
	}

	packetSource := gopacket.NewPacketSource(pcaph, pcaph.LinkType())
	packetSource.DecodeOptions = gopacket.DecodeOptions{Lazy: true, NoCopy: true}
	packets := packetSource.Packets()

	network := net.IPNet{
		IP:   net.ParseIP("172.168.10.10"),
		Mask: net.CIDRMask(24, 32),
	}

	engine := &Engine{
		LocalNetwork: network,
		LocalIP:      network.IP.To4(),
		LocalMAC:     netstack.OurMAC,
	}

	go func() {
		reply, err := arp.SendGratuitousArp(engine.LocalIP, engine.LocalMAC)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = pcaph.WritePacketData(reply)
		if err != nil {
			fmt.Println(err)
		}
	}()

	for packet := range packets {
		arpLayer, isArp := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
		if isArp {
			srcIP := net.IP(arpLayer.SourceProtAddress)
			dstIP := net.IP(arpLayer.DstProtAddress)
			if bytes.Compare(srcIP, engine.LocalIP) != 0 &&
				bytes.Compare(dstIP, engine.LocalIP) == 0 &&
				engine.LocalNetwork.Contains(srcIP) {
				reply, err := arp.SendReply(arpLayer, engine.LocalIP, engine.LocalMAC)
				if err != nil {
					fmt.Println(err)
					continue
				}

				err = pcaph.WritePacketData(reply)
				if err != nil {
					fmt.Println(err)
				}
				fmt.Println(packet.String())
				fmt.Println("ARP REPLY")
			}
		}

		ethernetLayer := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		iph, _ := net.ParseMAC("98:0d:af:de:21:96")
		if bytes.Equal(ethernetLayer.DstMAC, engine.LocalMAC) || bytes.Equal(ethernetLayer.SrcMAC, iph) {
			fmt.Println(packet.String())
		}

		//ipv4Layer, isIpV4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		//if isIpV4 && engine.LocalNetwork.Contains(ipv4Layer.SrcIP) {
		//	fmt.Println(packet.String())
		//}
	}

	return nil
}

type Engine struct {
	LocalNetwork net.IPNet
	LocalIP      net.IP
	LocalMAC     net.HardwareAddr
}
