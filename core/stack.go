package core

import (
	"github.com/DaniilSokolyuk/go-pcap2socks/core/adapter"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/option"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// Config is the configuration to create *stack.Stack.
type Config struct {
	// LinkEndpoints is the interface implemented by
	// data link layer protocols.
	LinkEndpoint stack.LinkEndpoint

	// TransportHandler is the handler used by internal
	// stack to set transport handlers.
	TransportHandler adapter.TransportHandler

	// Options are supplement options to apply settings
	// for the internal stack.
	Options []option.Option
}

// NewStack builds the stack, its protocol options and its transport handlers,
// and reserves the NIC id it will use.
//
// It deliberately stops short of creating the NIC. Creating one attaches the
// link endpoint, and attaching starts the dispatch loop, so anything that has
// to know about the stack before the first frame arrives - the device's
// neighbor learning, for one - gets its chance between this call and AttachNIC.
func NewStack(cfg *Config) (*stack.Stack, tcpip.NICID, error) {
	opts := []option.Option{option.WithDefault()}
	opts = append(opts, cfg.Options...)

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
			arp.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})

	nicID := s.NextNICID()

	opts = append(opts,
		// Important: We must initiate transport protocol handlers
		// before creating NIC, otherwise NIC would dispatch packets
		// to stack and cause race condition.
		// Initiate transport protocol (TCP/UDP) with given handler.
		withTCPHandler(cfg.TransportHandler.HandleTCP),
		withUDPNatHandler(nicID, cfg.TransportHandler.HandleUDP),
	)

	for _, opt := range opts {
		if err := opt(s); err != nil {
			s.Close()
			return nil, 0, err
		}
	}

	return s, nicID, nil
}

// AttachNIC binds ep to the stack and starts dispatching frames through it.
func AttachNIC(s *stack.Stack, nicID tcpip.NICID, ep stack.LinkEndpoint) error {
	opts := []option.Option{
		// Create stack NIC and then bind link endpoint to it.
		withCreatingNIC(nicID, ep),

		// In the past we did s.AddAddressRange to assign 0.0.0.0/0
		// onto the interface. We need that to be able to terminate
		// all the incoming connections - to any ip. AddressRange API
		// has been removed and the suggested workaround is to use
		// Promiscuous mode. https://github.com/google/gvisor/issues/3876
		//
		// Ref: https://github.com/cloudflare/slirpnetstack/blob/master/stack.go
		withPromiscuousMode(nicID, nicPromiscuousModeEnabled),

		// Enable spoofing if a stack may send packets from unowned
		// addresses. This change required changes to some netgophers
		// since previously, promiscuous mode was enough to let the
		// netstack respond to all incoming packets regardless of the
		// packet's destination address. Now that a stack.Route is not
		// held for each incoming packet, finding a route may fail with
		// local addresses we don't own but accepted packets for while
		// in promiscuous mode. Since we also want to be able to send
		// from any address (in response the received promiscuous mode
		// packets), we need to enable spoofing.
		//
		// Ref: https://github.com/google/gvisor/commit/8c0701462a84ff77e602f1626aec49479c308127
		withSpoofing(nicID, nicSpoofingEnabled),

		withRouteTable(nicID),
	}

	for _, opt := range opts {
		if err := opt(s); err != nil {
			return err
		}
	}

	return nil
}
