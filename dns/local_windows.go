//go:build windows

package dns

import (
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/miekg/dns"
	"golang.org/x/sys/windows"
)

// loadSystemConfig collects the DNS servers of every adapter that is up, in
// the order of the adapters' metrics.
func loadSystemConfig() (*dns.ClientConfig, error) {
	addresses, err := adapterAddresses()
	if err != nil {
		return nil, err
	}

	adapters := make([]adapter, 0, len(addresses))
	for _, aa := range addresses {
		a := adapter{
			up:       aa.OperStatus == windows.IfOperStatusUp,
			loopback: aa.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK,
			metric:   aa.Ipv4Metric,
		}
		for server := aa.FirstDnsServerAddress; server != nil; server = server.Next {
			rawSockaddr, err := server.Address.Sockaddr.Sockaddr()
			if err != nil {
				continue
			}
			switch sockaddr := rawSockaddr.(type) {
			case *syscall.SockaddrInet4:
				a.servers = append(a.servers, netip.AddrFrom4(sockaddr.Addr))
			case *syscall.SockaddrInet6:
				addr := netip.AddrFrom16(sockaddr.Addr)
				if sockaddr.ZoneId != 0 {
					addr = addr.WithZone(strconv.FormatInt(int64(sockaddr.ZoneId), 10))
				}
				a.servers = append(a.servers, addr)
			}
		}
		adapters = append(adapters, a)
	}

	return &dns.ClientConfig{
		Servers:  systemServers(adapters),
		Search:   []string{},
		Port:     "53",
		Ndots:    1,
		Timeout:  5,
		Attempts: 2,
	}, nil
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
