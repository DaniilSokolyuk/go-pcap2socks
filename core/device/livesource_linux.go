package device

import "net"

// newLiveSource opens the capture on a real interface.
func newLiveSource(ifce net.Interface, netConfig *NetworkConfig) (FrameSource, string, error) {
	src, err := newAFPacketSource(ifce, netConfig)
	if err != nil {
		return nil, "", err
	}
	return src, "afpacket", nil
}
