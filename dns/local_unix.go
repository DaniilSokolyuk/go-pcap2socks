//go:build !windows

package dns

import "github.com/miekg/dns"

// loadSystemConfig reads the resolver configuration the system publishes for
// programs like this one.
func loadSystemConfig() (*dns.ClientConfig, error) {
	return dns.ClientConfigFromFile("/etc/resolv.conf")
}
