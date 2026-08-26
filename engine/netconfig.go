package engine

import (
	"fmt"
	"net"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/device"
)

// ParseNetworkConfig validates the pcap section of the configuration against
// the interface it will run on.
func ParseNetworkConfig(pcapCfg cfg.PCAP, ifce net.Interface) (*device.NetworkConfig, error) {
	_, network, err := net.ParseCIDR(pcapCfg.Network)
	if err != nil {
		return nil, fmt.Errorf("parse cidr error: %w", err)
	}

	localIP := net.ParseIP(pcapCfg.LocalIP)
	if localIP == nil {
		return nil, fmt.Errorf("parse local ip error: %s", pcapCfg.LocalIP)
	}

	localIP = localIP.To4()
	if localIP == nil {
		return nil, fmt.Errorf("local ip must be IPv4: %s", pcapCfg.LocalIP)
	}

	if !network.Contains(localIP) {
		return nil, fmt.Errorf("local ip (%s) not in network (%s)", localIP, network)
	}

	var localMAC net.HardwareAddr
	if pcapCfg.LocalMAC != "" {
		localMAC, err = net.ParseMAC(pcapCfg.LocalMAC)
		if err != nil {
			return nil, fmt.Errorf("parse local mac error: %w", err)
		}
	} else {
		localMAC = ifce.HardwareAddr
	}

	if len(localMAC) != 6 {
		return nil, fmt.Errorf("local mac must be a 6 byte ethernet address, got %q", localMAC)
	}

	mtu := pcapCfg.MTU
	if mtu == 0 {
		mtu = uint32(ifce.MTU)
	}

	if mtu == 0 {
		return nil, fmt.Errorf("mtu is zero and could not be derived from interface %s", ifce.Name)
	}

	return &device.NetworkConfig{
		Network:  network,
		LocalIP:  localIP,
		LocalMAC: localMAC,
		MTU:      mtu,
	}, nil
}
