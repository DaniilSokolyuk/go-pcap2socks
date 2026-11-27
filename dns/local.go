package dns

import (
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// LocalClient resolves through the operating system's own DNS servers.
type LocalClient interface {
	Exchange(msg *dns.Msg) (*dns.Msg, error)
}

// configTTL is how long the system's DNS servers are remembered. Short enough
// that connecting a VPN or changing network is picked up almost at once, long
// enough that a burst of queries does not ask the system for each one.
const configTTL = 5 * time.Second

// serverTimeout is how long one server is given before the next is asked.
// Servers are asked in turn, so a dead one first in the list costs this much
// on every lookup; Windows itself gives up on a server after a second.
const serverTimeout = 2 * time.Second

type localClient struct {
	client *dns.Client

	mu       sync.Mutex
	config   *dns.ClientConfig
	loadedAt time.Time
}

func NewLocalClient() LocalClient {
	return &localClient{
		client: &dns.Client{
			Timeout: serverTimeout,
			UDPSize: dns.DefaultMsgSize,
		},
	}
}

// getConfig returns the system's DNS configuration, read again once it is
// older than configTTL.
func (lc *localClient) getConfig() (*dns.ClientConfig, error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if lc.config != nil && time.Since(lc.loadedAt) < configTTL {
		return lc.config, nil
	}
	config, err := loadSystemConfig()
	if err != nil {
		// A stale answer beats none while the network is changing.
		if lc.config != nil {
			return lc.config, nil
		}
		return nil, err
	}
	lc.config, lc.loadedAt = config, time.Now()
	return config, nil
}

func (lc *localClient) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	config, err := lc.getConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get DNS config: %w", err)
	}

	port := config.Port
	if port == "" {
		port = "53"
	}

	var lastErr error
	for _, server := range config.Servers {
		if server == "" {
			continue
		}
		response, _, err := lc.client.Exchange(msg, serverAddress(server, port))
		if err == nil {
			return response, nil
		}
		lastErr = err
	}

	if lastErr == nil {
		return nil, fmt.Errorf("no DNS servers configured")
	}
	return nil, lastErr
}
