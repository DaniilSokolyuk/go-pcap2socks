package cfg

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func Exists(filePath string) bool {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	}

	return true
}

func Load(filePath string) (*Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &Config{}
	decoder := json.NewDecoder(file)
	// A typo in a field name silently disables the field otherwise, which for a
	// hand-written config is much harder to notice than a startup error.
	decoder.DisallowUnknownFields()
	err = decoder.Decode(config)
	if err != nil {
		return nil, err
	}

	if err = config.Normalize(); err != nil {
		return nil, err
	}

	return config, nil
}

type Config struct {
	ExecuteOnStart []string `json:"executeOnStart"`
	PCAP           PCAP     `json:"pcap"`
	DNS            DNS      `json:"dns"`
	Routing        struct {
		Rules []Rule `json:"rules"`
	} `json:"routing"`
	Outbounds []Outbound `json:"outbounds"`
	Capture   Capture    `json:"capture,omitempty"`
}

type PCAP struct {
	InterfaceGateway string `json:"interfaceGateway"`
	MTU              uint32 `json:"mtu"`
	Network          string `json:"network"`
	LocalIP          string `json:"localIP"`
	LocalMAC         string `json:"localMAC"`
}

func (c *Config) Normalize() error {
	for i := range c.Routing.Rules {
		if err := c.Routing.Rules[i].Normalize(); err != nil {
			return fmt.Errorf("routing rule %d: %w", i, err)
		}
	}

	return nil
}

type Rule struct {
	SrcPort     string   `json:"srcPort,omitempty"`
	DstPort     string   `json:"dstPort,omitempty"`
	SrcIP       []string `json:"srcIP,omitempty"`
	DstIP       []string `json:"dstIP,omitempty"`
	OutboundTag string   `json:"outboundTag"`

	SrcPorts map[uint16]struct{}
	DstPorts map[uint16]struct{}
	SrcIPs   []net.IPNet
	DstIPs   []net.IPNet
}

func (r *Rule) Normalize() (err error) {
	if r.SrcPorts, err = ParsePorts(r.SrcPort); err != nil {
		return fmt.Errorf("srcPort: %w", err)
	}
	if r.DstPorts, err = ParsePorts(r.DstPort); err != nil {
		return fmt.Errorf("dstPort: %w", err)
	}
	if r.SrcIPs, err = ParseCIDRs(r.SrcIP); err != nil {
		return fmt.Errorf("srcIP: %w", err)
	}
	if r.DstIPs, err = ParseCIDRs(r.DstIP); err != nil {
		return fmt.Errorf("dstIP: %w", err)
	}

	return nil
}

type Outbound struct {
	Direct *OutboundDirect `json:"direct,omitempty"`
	Socks  *OutboundSocks  `json:"socks,omitempty"`
	Reject *OutboundReject `json:"reject,omitempty"`
	DNS    *OutboundDNS    `json:"dns,omitempty"`
	Tag    string          `json:"tag,omitempty"`
}

type OutboundDirect struct{}
type OutboundReject struct{}

type OutboundSocks struct {
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type OutboundDNS struct{}

type DNS struct {
	Servers []struct {
		Address string `json:"address"`
	}
}

type Capture struct {
	Enabled    bool   `json:"enabled"`
	OutputFile string `json:"outputFile"`
}

// ParseCIDRs parses a list of addresses into networks. A plain address without
// a prefix length is treated as a single host (/32 for IPv4, /128 for IPv6).
func ParseCIDRs(addrs []string) ([]net.IPNet, error) {
	ips := make([]net.IPNet, 0, len(addrs))

	for _, addr := range addrs {
		cidr := addr
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid ip %q: %w", addr, err)
		}

		ips = append(ips, *ipNet)
	}

	return ips, nil
}

// ParsePorts parses a comma separated list of ports and inclusive port ranges,
// e.g. "53, 80, 8000-9000".
func ParsePorts(ports string) (map[uint16]struct{}, error) {
	m := make(map[uint16]struct{})

	if strings.TrimSpace(ports) == "" {
		return m, nil
	}

	for _, port := range strings.Split(ports, ",") {
		port = strings.TrimSpace(port)

		if lo, hi, isRange := strings.Cut(port, "-"); isRange {
			mmin, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", lo, err)
			}

			mmax, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", hi, err)
			}

			if mmin > mmax {
				return nil, fmt.Errorf("invalid port range %q: start is greater than end", port)
			}

			for i := mmin; i <= mmax; i++ {
				m[uint16(i)] = struct{}{}
			}

			continue
		}

		parsed, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", port, err)
		}

		m[uint16(parsed)] = struct{}{}
	}

	return m, nil
}
