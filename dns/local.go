package dns

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

type LocalClient interface {
	Exchange(msg *dns.Msg) (*dns.Msg, error)
}

type localClient struct {
	client        *dns.Client
	config        *dns.ClientConfig
	currentTime   func() time.Time
	interfaceName string
}

func NewLocalClient(interfaceName string) LocalClient {
	return &localClient{
		client: &dns.Client{
			Timeout: 5 * time.Second,
			UDPSize: dns.DefaultMsgSize,
		},
		currentTime:   time.Now,
		interfaceName: interfaceName,
	}
}

func (lc *localClient) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	config, err := lc.getConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get DNS config: %w", err)
	}

	var lastErr error
	for _, server := range config.Servers {
		if server == "" {
			continue
		}

		serverAddr := server
		if config.Port != "" && config.Port != "53" {
			serverAddr = fmt.Sprintf("%s:%s", server, config.Port)
		} else if len(server) > 0 && server[0] == '[' {
			serverAddr = server + ":53"
		} else {
			serverAddr = server + ":53"
		}

		response, _, err := lc.client.Exchange(msg, serverAddr)
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
