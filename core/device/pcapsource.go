//go:build !linux

package device

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"runtime"

	"github.com/gopacket/gopacket/pcap"
)

// pcapSource is the FrameSource for every platform but Linux, backed by a
// live pcap handle. Linux talks to the kernel itself, see afpacket_linux.go.
type pcapSource struct {
	handle *pcap.Handle
	// tx sends a batch in one call where the platform can; nil where it
	// cannot, and then frames go out one at a time.
	tx frameSender
}

var (
	_ FrameSource       = (*pcapSource)(nil)
	_ BatchWriter       = (*pcapSource)(nil)
	_ ChecksumOffloader = (*pcapSource)(nil)
)

// captureSnapLen is how much of a frame is captured: all of it, whatever its
// size. A network adapter that coalesces received TCP segments (RSC on
// Windows, LRO elsewhere) hands the capture packets of up to 64KB, and
// anything shorter than that truncates them. The stack discards a truncated
// packet, so a bulk upload from the device crawls with nothing in the log;
// this is what a snap length of 1600 did.
const captureSnapLen = 1<<16 + 32

// captureBufferSize is the kernel buffer for captured frames. Npcap takes
// whatever it is asked for, and needs more than the old half megabyte now
// that one packet can be 64KB. A BPF device is capped by the system
// (debug.bpf_maxbufsize, 512KB by default on macOS) and refuses more.
func captureBufferSize() int {
	if runtime.GOOS == "windows" {
		return 4 << 20
	}
	return 512 * 1024
}

// RXChecksumOffload reports that IP and transport checksums of captured packets must
// not be verified. A coalesced packet carries a checksum that is not valid on
// its own; the adapter verified the segments before merging them.
func (p *pcapSource) RXChecksumOffload() bool { return true }

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

	src := &pcapSource{handle: handle}
	if tx, err := newPcapFrameSender(handle); err != nil {
		slog.Warn("batched sending is unavailable, sending one frame at a time", "reason", err)
	} else {
		src.tx = tx
	}
	return src, nil
}

// WriteFrames sends a batch of frames, in one call where the platform has a
// way to do that.
func (p *pcapSource) WriteFrames(frames [][]byte) error {
	if p.tx != nil {
		return p.tx.send(frames)
	}
	for _, frame := range frames {
		if err := p.handle.WritePacketData(frame); err != nil {
			return err
		}
	}
	return nil
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
	if p.tx != nil {
		_ = p.tx.close()
	}
	p.handle.Close()
	return nil
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

	err = handle.SetSnapLen(captureSnapLen)
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

	err = handle.SetBufferSize(captureBufferSize())
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
