package arpr

import (
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func SendGratuitousArp(localIP net.IP, localMAC net.HardwareAddr) ([]byte, error) {
	// net.ParseIP and net.IPv4 hand back a 16 byte representation for IPv4
	// literals; ARP needs the 4 byte one or the protocol address size ends up
	// wrong and receivers discard the frame.
	ip4 := localIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("gratuitous arp requires an IPv4 address, got %s", localIP)
	}

	if len(localMAC) != 6 {
		return nil, fmt.Errorf("gratuitous arp requires a 6 byte MAC address, got %s", localMAC)
	}

	ethernet := &layers.Ethernet{
		SrcMAC:       localMAC,
		DstMAC:       layers.EthernetBroadcast,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   localMAC,
		SourceProtAddress: ip4,
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    ip4,
	}

	sbuf := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(sbuf, options, ethernet, arp); err != nil {
		return nil, err
	}

	return sbuf.Bytes(), nil
}
