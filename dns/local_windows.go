//go:build windows

package dns

import (
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"github.com/miekg/dns"
	"golang.org/x/sys/windows"
)

func (lc *localClient) getConfig() (*dns.ClientConfig, error) {
	if lc.config == nil {
		config := &dns.ClientConfig{
			Servers:  []string{},
			Search:   []string{},
			Port:     "53",
			Ndots:    1,
			Timeout:  5,
			Attempts: 2,
		}

		addresses, err := adapterAddresses()
		if err != nil {
			return nil, err
		}

		var dnsAddresses []struct {
			ifName string
			netip.Addr
		}
		for _, address := range addresses {
			if address.OperStatus != windows.IfOperStatusUp {
				continue
			}
			if address.IfType == windows.IF_TYPE_TUNNEL {
				continue
			}
			if address.FirstGatewayAddress == nil {
				continue
			}
			for dnsServerAddress := address.FirstDnsServerAddress; dnsServerAddress != nil; dnsServerAddress = dnsServerAddress.Next {
				rawSockaddr, err := dnsServerAddress.Address.Sockaddr.Sockaddr()
				if err != nil {
					continue
				}
				var dnsServerAddr netip.Addr
				switch sockaddr := rawSockaddr.(type) {
				case *syscall.SockaddrInet4:
					dnsServerAddr = netip.AddrFrom4(sockaddr.Addr)
				case *syscall.SockaddrInet6:
					if sockaddr.Addr[0] == 0xfe && sockaddr.Addr[1] == 0xc0 {
						// fec0/10 IPv6 addresses are site local anycast DNS
						// addresses Microsoft sets by default if no other
						// IPv6 DNS address is set. Site local anycast is
						// deprecated since 2004, see
						// https://datatracker.ietf.org/doc/html/rfc3879
						continue
					}
					dnsServerAddr = netip.AddrFrom16(sockaddr.Addr)
				default:
					// Unexpected type.
					continue
				}
				dnsAddresses = append(dnsAddresses, struct {
					ifName string
					netip.Addr
				}{ifName: windows.UTF16PtrToString(address.FriendlyName), Addr: dnsServerAddr})
			}
		}

		// Filter out DNS servers from the interface we're using
		for _, address := range dnsAddresses {
			if address.ifName == lc.interfaceName {
				continue
			}
			config.Servers = append(config.Servers, net.JoinHostPort(address.Addr.String(), "53"))
		}

		lc.config = config
	}
	return lc.config, nil
}

func adapterAddresses() ([]*windows.IpAdapterAddresses, error) {
	var b []byte
	l := uint32(15000) // recommended initial size
	for {
		b = make([]byte, l)
		const flags = windows.GAA_FLAG_INCLUDE_PREFIX | windows.GAA_FLAG_INCLUDE_GATEWAYS
		err := windows.GetAdaptersAddresses(syscall.AF_UNSPEC, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &l)
		if err == nil {
			if l == 0 {
				return nil, nil
			}
			break
		}
		if err.(syscall.Errno) != syscall.ERROR_BUFFER_OVERFLOW {
			return nil, os.NewSyscallError("getadaptersaddresses", err)
		}
		if l <= uint32(len(b)) {
			return nil, os.NewSyscallError("getadaptersaddresses", err)
		}
	}
	var aas []*windows.IpAdapterAddresses
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])); aa != nil; aa = aa.Next {
		aas = append(aas, aa)
	}
	return aas, nil
}
