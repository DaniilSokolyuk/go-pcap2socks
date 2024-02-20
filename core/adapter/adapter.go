package adapter

import (
	M "github.com/DaniilSokolyuk/go-pcap2socks/md"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TCPConn implements the net.Conn interface.
type TCPConn interface {
	net.Conn

	// ID returns the transport endpoint id of TCPConn.
	ID() *stack.TransportEndpointID
}

// UDPConn implements net.Conn and net.PacketConn.
type UDPConn interface {
	net.PacketConn

	MD() *M.Metadata
}
