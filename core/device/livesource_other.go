//go:build !linux

package device

import "net"

// newLiveSource opens the capture on a real interface.
func newLiveSource(ifce net.Interface, netConfig *NetworkConfig) (FrameSource, string, error) {
	src, err := newPcapSource(ifce, netConfig)
	if err != nil {
		return nil, "", err
	}
	return src, "pcap", nil
}
