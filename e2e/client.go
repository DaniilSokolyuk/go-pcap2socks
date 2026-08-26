package e2e

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const clientNICID tcpip.NICID = 1

// Client is a fake console: an ordinary gVisor stack with an IP address and a
// default route through the gateway, speaking real ethernet onto the wire.
// Test "apps" run on top of it via DialTCP/DialUDP.
type Client struct {
	IP  netip.Addr
	MAC net.HardwareAddr

	stack *stack.Stack
	ch    *channel.Endpoint
}

// NewClient builds the client stack. It does not connect it to anything; the
// harness wires it to the device.
func NewClient(ip netip.Addr, mac net.HardwareAddr, gateway netip.Addr, prefixLen int, mtu uint32) (*Client, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			arp.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
		},
	})

	linkAddr, err := tcpip.ParseMACAddress(mac.String())
	if err != nil {
		return nil, fmt.Errorf("parse client mac: %w", err)
	}

	ch := channel.New(512, mtu, linkAddr)

	if err := s.CreateNIC(clientNICID, ethernet.New(ch)); err != nil {
		return nil, fmt.Errorf("create client nic: %s", err)
	}

	addr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(ip.As4()),
			PrefixLen: prefixLen,
		},
	}
	if err := s.AddProtocolAddress(clientNICID, addr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add client address: %s", err)
	}

	// Everything goes through the gateway, exactly like a console configured
	// to use go-pcap2socks as its router. Off-link destinations therefore make
	// the client ARP for the gateway first.
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		Gateway:     tcpip.AddrFrom4(gateway.As4()),
		NIC:         clientNICID,
	}})

	return &Client{IP: ip, MAC: mac, stack: s, ch: ch}, nil
}

// DialTCP opens a TCP connection to addr through the gateway.
func (c *Client) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return gonet.DialContextTCP(ctx, c.stack, fullAddr(addr), ipv4.ProtocolNumber)
}

// DialUDP opens an unconnected UDP socket bound to a random local port.
func (c *Client) DialUDP() (*gonet.UDPConn, error) {
	var wq waiter.Queue
	ep, err := c.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		return nil, fmt.Errorf("new udp endpoint: %s", err)
	}

	local := tcpip.FullAddress{NIC: clientNICID, Addr: tcpip.AddrFrom4(c.IP.As4())}
	if err := ep.Bind(local); err != nil {
		ep.Close()
		return nil, fmt.Errorf("bind udp endpoint: %s", err)
	}

	return gonet.NewUDPConn(&wq, ep), nil
}

// InjectFrame pushes a raw ethernet frame onto the wire as if the client had
// sent it. Used by tests that need to craft packets by hand.
func (c *Client) InjectFrame(frame []byte) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(frame),
	})
	c.ch.InjectInbound(header.EthernetProtocolAll, pkt)
	pkt.DecRef()
}

// Close shuts the client stack down.
func (c *Client) Close() {
	c.stack.Close()
	c.ch.Close()
	c.stack.Wait()
}

func fullAddr(addr netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{
		NIC:  clientNICID,
		Addr: tcpip.AddrFrom4(addr.Addr().As4()),
		Port: addr.Port(),
	}
}
