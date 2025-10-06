package device

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// pcapICMPSender implements iobased.ICMPSender for Path MTU Discovery via ICMP.
// It sends ICMP Type 3 Code 4 (Fragmentation Needed) messages when packets exceed MTU.
type pcapICMPSender struct {
	writer interface {
		Write([]byte) (int, error)
	}
	localMAC   net.HardwareAddr
	localIP    net.IP
	ipMacTable map[string]net.HardwareAddr
}

func (s *pcapICMPSender) SendICMPFragmentationNeeded(srcIP, dstIP []byte, mtu uint32, originalPacket []byte) error {
	// Validate inputs
	if len(srcIP) != 4 || len(dstIP) != 4 {
		return fmt.Errorf("invalid IP addresses: src=%v dst=%v", srcIP, dstIP)
	}

	// Look up destination MAC address from IP-MAC table
	dstMAC, exists := s.ipMacTable[string(srcIP)]
	if !exists {
		// If we don't have the MAC address, we can't send the ICMP packet
		slog.Debug("[ICMP] Cannot send ICMP - no MAC address for IP", "ip", srcIP)
		return fmt.Errorf("no MAC address for IP %v", srcIP)
	}

	// Log original packet for debugging
	if slog.Default().Enabled(nil, slog.LevelDebug) {
		packet := gopacket.NewPacket(originalPacket, layers.LayerTypeIPv4, gopacket.Default)
		slog.Debug("[ICMP] Original packet to include in ICMP",
			"packet", packet.String(),
			"size", len(originalPacket))
	}

	// Extract original IP header + 8 bytes for ICMP payload
	if len(originalPacket) < header.IPv4MinimumSize {
		return fmt.Errorf("original packet too small: %d bytes", len(originalPacket))
	}
	dataToInclude := 8
	if len(originalPacket) < header.IPv4MinimumSize+dataToInclude {
		dataToInclude = len(originalPacket) - header.IPv4MinimumSize
	}
	originalData := originalPacket[:header.IPv4MinimumSize+dataToInclude]

	slog.Debug("[ICMP] ICMP payload breakdown",
		"ip_header_size", header.IPv4MinimumSize,
		"data_to_include", dataToInclude,
		"total_original_data", len(originalData),
		"icmp_payload_size", 4+len(originalData))

	// For ICMP Type 3 Code 4, the format after Type/Code/Checksum is:
	// [unused (2 bytes, mapped to Id)] [MTU (2 bytes, mapped to Seq)] [original IP + 8 bytes data]
	// gopacket uses Id/Seq fields, so we put MTU in Seq field

	// Create Ethernet layer (like in ARP)
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       s.localMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create IP layer
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    s.localIP,
		DstIP:    net.IP(srcIP),
	}

	// Create ICMP layer
	// RFC 1191 (Path MTU Discovery): "the router MUST include the MTU of
	// that next-hop network in the low-order 16 bits of the ICMP header
	// field that is labelled 'unused' in the ICMP specification"
	// gopacket maps: Id field = high-order 16 bits (unused=0), Seq field = low-order 16 bits (MTU)
	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(3, 4), // Type 3 Code 4: Fragmentation Needed
		Id:       0,                                 // High-order 16 bits: unused (must be 0)
		Seq:      uint16(mtu),                       // Low-order 16 bits: Next-Hop MTU (RFC 1191)
	}

	// Serialize with Ethernet layer included (like ARP does)
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	//0                   1                   2                   3
	//0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//|   Type = 3    |   Code = 4    |           Checksum            |
	//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//|           unused = 0          |         Next-Hop MTU          |
	//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//|      Internet Header + 64 bits of Original Datagram Data      |
	//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	// Payload is original IP header + 8 bytes of data (no manual MTU bytes needed)
	err := gopacket.SerializeLayers(buffer, opts,
		ethernetLayer,
		ipLayer,
		icmpLayer,
		gopacket.Payload(originalData), // Just original IP header + 8 bytes
	)
	if err != nil {
		return fmt.Errorf("failed to serialize ICMP packet: %w", err)
	}

	// Write the complete Ethernet frame
	packet := buffer.Bytes()

	// Log final ICMP packet
	if slog.Default().Enabled(nil, slog.LevelDebug) {
		finalPacket := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.Default)
		slog.Debug("[ICMP] Final ICMP packet to send",
			"packet", finalPacket.String(),
			"total_size", len(packet))
	}

	_, err = s.writer.Write(packet)
	if err != nil {
		return fmt.Errorf("failed to write Ethernet frame: %w", err)
	}

	slog.Info("[ICMP] Sent ICMP Fragmentation Needed via Ethernet",
		"src_ip", s.localIP.String(), // Gateway IP
		"dst_ip", fmt.Sprintf("%d.%d.%d.%d", srcIP[0], srcIP[1], srcIP[2], srcIP[3]),
		"dst_mac", dstMAC.String(),
		"mtu", mtu)

	return nil
}
