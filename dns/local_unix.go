//go:build !windows

package dns

import (
	"github.com/miekg/dns"
)

func (lc *localClient) getConfig() (*dns.ClientConfig, error) {
	if lc.config == nil {
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, err
		}
		lc.config = config
	}
	return lc.config, nil
}
