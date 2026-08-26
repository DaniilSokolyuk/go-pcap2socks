package device

import (
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Device is the interface that implemented by network layer devices (e.g. tun),
// and easy to use as stack.LinkEndpoint.
type Device interface {
	stack.LinkEndpoint

	// Name returns the current name of the device.
	Name() string

	// Type returns the driver type of the device.
	Type() string

	// Done is closed when the device stops reading frames: the source was
	// closed or failed, and no further traffic will arrive.
	Done() <-chan struct{}

	// AttachNeighborCache hands the device somewhere to record the addresses it
	// learns. It must be called before the stack creates its NIC: creating the
	// NIC attaches this endpoint, which is what starts the dispatch loop.
	AttachNeighborCache(nc NeighborCache, nicID tcpip.NICID)
}

// NetworkConfig holds the parsed network configuration
type NetworkConfig struct {
	Network  *net.IPNet
	LocalIP  net.IP
	LocalMAC net.HardwareAddr
	MTU      uint32
}
