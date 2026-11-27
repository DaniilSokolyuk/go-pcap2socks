package dns

import (
	"net"
	"net/netip"
	"sort"
)

// serverAddress joins a server from the system configuration with a port. An
// IPv6 server needs brackets, which a plain concatenation would leave out.
func serverAddress(server, port string) string {
	if len(server) > 0 && server[0] == '[' {
		return server + ":" + port
	}
	return net.JoinHostPort(server, port)
}

// adapter is what the choice of DNS servers needs to know about a network
// adapter.
type adapter struct {
	up       bool
	loopback bool
	// metric is the adapter's route metric: the lower, the more the system
	// prefers it. A VPN gives itself a low metric to take over.
	metric  uint32
	servers []netip.Addr
}

// systemServers lists the DNS servers of every adapter that is up, most
// preferred adapter first, the way the system itself would consult them.
//
// It deliberately does not look only at the adapter traffic is captured on.
// A VPN puts its resolver on its own adapter, and the resolver of the
// physical one is exactly what the user turned the VPN on to get away from.
func systemServers(adapters []adapter) []string {
	usable := make([]adapter, 0, len(adapters))
	for _, a := range adapters {
		if a.up && !a.loopback && len(a.servers) > 0 {
			usable = append(usable, a)
		}
	}
	sort.SliceStable(usable, func(i, j int) bool { return usable[i].metric < usable[j].metric })

	var servers []string
	seen := make(map[netip.Addr]bool)
	for _, a := range usable {
		for _, server := range a.servers {
			// fec0::/10 are the site local anycast addresses Windows fills
			// in when an adapter has no IPv6 DNS server. They were deprecated
			// in 2004 (RFC 3879) and nothing answers there.
			if server.Is6() && server.As16()[0] == 0xfe && server.As16()[1]&0xc0 == 0xc0 {
				continue
			}
			if seen[server] {
				continue
			}
			seen[server] = true
			servers = append(servers, server.String())
		}
	}
	return servers
}
