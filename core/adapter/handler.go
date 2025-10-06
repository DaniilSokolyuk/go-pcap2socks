package adapter

// TransportHandler is a TCP/UDP connection handler that implements
// HandleTCP and HandleUDP methods.
type TransportHandler interface {
	HandleTCP(TCPConn)
	HandleUDP(UDPConn)
}

// ICMPSender is an interface for sending ICMP messages.
// This is used for Path MTU Discovery and other ICMP operations.
type ICMPSender interface {
	// SendICMPFragmentationNeeded sends an ICMP "Fragmentation Needed" message
	// to the source when a packet is too large for the MTU.
	SendICMPFragmentationNeeded(srcIP, dstIP []byte, mtu uint32, originalPacket []byte) error
}
