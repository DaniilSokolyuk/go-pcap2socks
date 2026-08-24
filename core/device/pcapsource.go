package device

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"

	"github.com/gopacket/gopacket/pcap"
)

// pcapSource is the production FrameSource, backed by a live pcap handle.
type pcapSource struct {
	handle *pcap.Handle
}

var _ FrameSource = (*pcapSource)(nil)

func newPcapSource(ifce net.Interface, netConfig *NetworkConfig) (*pcapSource, error) {
	dev, err := findPcapDevice(ifce)
	if err != nil {
		return nil, err
	}

	handle, promiscErr, err := activate(dev, true)
	if isPromiscUnsupported(err) {
		// libpcap reports this as a warning (PCAP_WARNING_PROMISC_NOTSUP) but
		// gopacket surfaces it as an error and throws the handle away, so the
		// only way forward is to activate again without it. macOS Wi-Fi
		// interfaces routinely refuse promiscuous mode.
		//
		// Capture still works: devices address their frames to our MAC after
		// resolving the gateway, and ARP is broadcast. The exception is a
		// configured localMAC that differs from the interface's own address -
		// those frames are only visible in promiscuous mode.
		if !bytes.Equal(netConfig.LocalMAC, ifce.HardwareAddr) {
			return nil, fmt.Errorf(
				"promiscuous mode is unavailable on %s, so frames addressed to the configured localMAC %s would never reach us; "+
					"remove localMAC from the config to use the interface address %s",
				ifce.Name, netConfig.LocalMAC, ifce.HardwareAddr)
		}

		slog.Warn("promiscuous mode is not supported on this interface, capturing without it",
			"interface", ifce.Name, "reason", promiscErr)
		handle, _, err = activate(dev, false)
	}
	if err != nil {
		return nil, fmt.Errorf("open live error: %w", err)
	}

	if err = handle.SetBPFFilter(BPFFilter(netConfig)); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set bpf filter error: %w", err)
	}

	return &pcapSource{handle: handle}, nil
}

func (p *pcapSource) ReadFrame() ([]byte, error) {
	data, _, err := p.handle.ZeroCopyReadPacketData()
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (p *pcapSource) WriteFrame(frame []byte) error {
	return p.handle.WritePacketData(frame)
}

func (p *pcapSource) Close() error {
	p.handle.Close()
	return nil
}

// BPFFilter builds the capture filter for the configured network.
//
// 1. ARP packets: (arp dst host <localIP> and arp src net <network> and not arp src host <localIP>)
//   - Only ARP requests TO us (arp dst host)
//   - From devices in our network (arp src net)
//   - Not from ourselves (not arp src host) - loop prevention
//
// 2. IPv4 packets: (src net <network> and not dst net <network> and not (icmp and src host <localIP>))
//   - All IPv4 packets from the configured network
//   - Not destined to the local network (only capture internet-bound traffic)
//   - Exclude ICMP from ourselves (loop prevention in promiscuous mode)
//
// ARP field access in BPF:
//   - "arp src host X" / "arp src net X" - checks Source Protocol Address (SPA) field
//   - "arp dst host X" / "arp dst net X" - checks Target Protocol Address (TPA) field
func BPFFilter(netConfig *NetworkConfig) string {
	return fmt.Sprintf(
		"(arp dst host %s and arp src net %s and not arp src host %s) or (src net %s and not dst net %s and not (icmp and src host %s))",
		netConfig.LocalIP.String(),
		netConfig.Network.String(),
		netConfig.LocalIP.String(),
		netConfig.Network.String(),
		netConfig.Network.String(),
		netConfig.LocalIP.String(),
	)
}

// isPromiscUnsupported reports whether activation failed only because the
// interface does not support promiscuous mode. gopacket keeps the underlying
// activateError type unexported, so its message is all there is to match on.
func isPromiscUnsupported(err error) bool {
	return err != nil && err.Error() == "Cannot set as promisc"
}

// activate opens the handle. On failure it also returns libpcap's own error
// buffer, which carries the errno behind a promiscuous mode failure; gopacket
// only surfaces its generic message for that case.
func activate(dev pcap.Interface, promisc bool) (handle *pcap.Handle, detail error, err error) {
	inactive, err := createPcapHandle(dev, promisc)
	if err != nil {
		return nil, nil, err
	}
	defer inactive.CleanUp()

	handle, err = inactive.Activate()
	if err != nil {
		// Only reachable here: a successful Activate hands the underlying
		// pcap_t over to the Handle and leaves the InactiveHandle holding a nil
		// pointer, which Error() would dereference without checking.
		return nil, inactive.Error(), err
	}

	return handle, nil, nil
}

func createPcapHandle(dev pcap.Interface, promisc bool) (*pcap.InactiveHandle, error) {
	handle, err := pcap.NewInactiveHandle(dev.Name)
	if err != nil {
		return nil, fmt.Errorf("new inactive handle error: %w", err)
	}

	err = handle.SetPromisc(promisc)
	if err != nil {
		return nil, fmt.Errorf("set promisc error: %w", err)
	}

	err = handle.SetSnapLen(1600)
	if err != nil {
		return nil, fmt.Errorf("set snap len error: %w", err)
	}

	err = handle.SetTimeout(pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("set timeout error: %w", err)
	}

	err = handle.SetImmediateMode(true)
	if err != nil {
		return nil, fmt.Errorf("set immediate mode error: %w", err)
	}

	err = handle.SetBufferSize(512 * 1024)
	if err != nil {
		return nil, fmt.Errorf("set buffer size error: %w", err)
	}

	return handle, nil
}

func findPcapDevice(ifce net.Interface) (pcap.Interface, error) {
	// Get all pcap devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return pcap.Interface{}, fmt.Errorf("find all devices error: %w", err)
	}

	// Get interface addresses
	addrs, err := ifce.Addrs()
	if err != nil {
		return pcap.Interface{}, fmt.Errorf("get interface addresses error: %w", err)
	}

	// Find matching device
	for _, dev := range devices {
		for _, devAddr := range dev.Addresses {
			for _, ifaceAddr := range addrs {
				if ipnet, ok := ifaceAddr.(*net.IPNet); ok {
					if devAddr.IP.Equal(ipnet.IP) {
						return dev, nil
					}
				}
			}
		}
	}

	return pcap.Interface{}, fmt.Errorf("pcap device not found for interface %s", ifce.Name)
}
