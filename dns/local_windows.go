//go:build windows

package dns

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/miekg/dns"
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

		// Try to get DNS servers using netsh command
		cmd := exec.Command("netsh", "interface", "ip", "show", "dnsservers")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if ip := net.ParseIP(line); ip != nil {
					config.Servers = append(config.Servers, ip.String())
				}
			}
		}

		// Fallback to common DNS servers if we couldn't get any
		if len(config.Servers) == 0 {
			config.Servers = []string{"8.8.8.8", "8.8.4.4"}
		}

		lc.config = config
	}
	return lc.config, nil
}
