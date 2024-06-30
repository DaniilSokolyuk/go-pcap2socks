package arpr

import (
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func SendGratuitousArp(localIP net.IP, localMAC net.HardwareAddr) ([]byte, error) {
	ethernet := &layers.Ethernet{
		SrcMAC:       localMAC,
		DstMAC:       layers.EthernetBroadcast,
		EthernetType: layers.EthernetTypeIPv4,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   localMAC,
		SourceProtAddress: localIP,
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    localIP,
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

func SendReply(arp *layers.ARP, localIP net.IP, localMAC net.HardwareAddr) ([]byte, error) {
	if arp.Operation != layers.ARPRequest {
		return nil, fmt.Errorf("not an ARP request")
	}

	ethernetResp := &layers.Ethernet{
		SrcMAC:       localMAC,
		DstMAC:       arp.SourceHwAddress,
		EthernetType: layers.EthernetTypeARP,
	}
	arpResp := &layers.ARP{
		AddrType:          arp.AddrType,
		Protocol:          arp.Protocol,
		HwAddressSize:     arp.HwAddressSize,
		ProtAddressSize:   arp.ProtAddressSize,
		Operation:         layers.ARPReply,
		SourceHwAddress:   localMAC,
		SourceProtAddress: localIP,
		DstHwAddress:      arp.SourceHwAddress,
		DstProtAddress:    arp.SourceProtAddress,
	}

	sbuf := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(sbuf, options, ethernetResp, arpResp); err != nil {
		panic(err)
	}

	// If we failed to write the message, we do so silently. Packet loss happen...
	return sbuf.Bytes(), nil
}
