package core

import (
	"fmt"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/option"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"net"
)

func withRouteTable(nicID tcpip.NICID) option.Option {
	return func(s *stack.Stack) error {
		s.SetRouteTable([]tcpip.Route{
			{
				Destination: header.IPv4EmptySubnet,
				NIC:         nicID,
			},
			{
				Destination: header.IPv6EmptySubnet,
				NIC:         nicID,
			},
		})
		return nil
	}
}

func setupNetwork(nicID tcpip.NICID, assignNet string) option.Option {
	return func(s *stack.Stack) error {
		ipAddr, ipNet, err := net.ParseCIDR(assignNet)
		if err != nil {
			panic(fmt.Sprintf("Unable to ParseCIDR(%s): %s", assignNet, err))
		}

		if ipAddr.To4() != nil {
			s.AddProtocolAddress(
				nicID,
				tcpip.ProtocolAddress{
					Protocol: ipv4.ProtocolNumber,
					AddressWithPrefix: tcpip.AddressWithPrefix{
						Address:   tcpip.AddrFrom4Slice(ipAddr.To4()),
						PrefixLen: tcpip.MaskFromBytes(ipNet.Mask).Prefix(),
					},
				},
				stack.AddressProperties{PEB: stack.CanBePrimaryEndpoint},
			)
		} else {
			s.AddProtocolAddress(
				nicID,
				tcpip.ProtocolAddress{
					Protocol: ipv6.ProtocolNumber,
					AddressWithPrefix: tcpip.AddressWithPrefix{
						Address:   tcpip.AddrFrom16Slice(ipAddr.To16()),
						PrefixLen: tcpip.MaskFromBytes(ipNet.Mask).Prefix(),
					},
				},
				stack.AddressProperties{PEB: stack.CanBePrimaryEndpoint},
			)
		}

		rt := s.GetRouteTable()
		rt = append(rt, tcpip.Route{
			Destination: *MustSubnet(ipNet),
			NIC:         nicID,
		})
		s.SetRouteTable(rt)

		return nil
	}
}

func MustSubnet(ipNet *net.IPNet) *tcpip.Subnet {
	subnet, errx := tcpip.NewSubnet(tcpip.AddrFromSlice(ipNet.IP), tcpip.MaskFromBytes(ipNet.Mask))
	if errx != nil {
		panic(fmt.Sprintf("Unable to MustSubnet(%s): %s", ipNet, errx))
	}
	return &subnet
}
