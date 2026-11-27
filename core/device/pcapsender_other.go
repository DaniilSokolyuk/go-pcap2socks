//go:build !linux && !windows

package device

import "github.com/gopacket/gopacket/pcap"

// newPcapFrameSender has nothing to offer on macOS and the BSDs: a BPF device
// takes exactly one frame per write, so there is no call that sends several.
func newPcapFrameSender(*pcap.Handle) (frameSender, error) {
	return nil, nil
}
