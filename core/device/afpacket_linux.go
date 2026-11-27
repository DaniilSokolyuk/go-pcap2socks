package device

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket/afpacket"
)

// afpacketSource is the FrameSource for Linux. It talks to the kernel
// directly, without libpcap and so without cgo: gopacket's afpacket ring for capture, and
// packetSender for transmit, because afpacket can only send a frame at a time.
//
// The ring is TPACKET_V2, the same choice libpcap makes in immediate mode: V3
// hands frames over a block at a time, which adds up to a block timeout of
// latency to every packet on a quiet link. With V2 a frame is visible the
// moment the kernel writes it, and frames that arrive while the previous one
// is being processed are picked up without a system call at all.
type afpacketSource struct {
	ring   *afpacket.TPacket
	tx     frameSender
	closed atomic.Bool
}

var (
	_ FrameSource = (*afpacketSource)(nil)
	_ BatchWriter = (*afpacketSource)(nil)
)

const (
	// Room for the ring's own header and a full ethernet frame.
	ringFrameSize = 2048
	// A multiple of every page size in use (4K, 16K, 64K) and of the frame
	// size.
	ringBlockSize = 1 << 20
	ringBlocks    = 4

	// How long a read waits before checking whether the source was closed.
	closePoll = 100 * time.Millisecond
)

func newAFPacketSource(ifce net.Interface, netConfig *NetworkConfig) (*afpacketSource, error) {
	filter, err := CaptureFilter(netConfig)
	if err != nil {
		return nil, err
	}

	ring, err := afpacket.NewTPacket(
		afpacket.OptInterface(ifce.Name),
		afpacket.SocketRaw,
		afpacket.TPacketVersion2,
		afpacket.OptFrameSize(ringFrameSize),
		afpacket.OptBlockSize(ringBlockSize),
		afpacket.OptNumBlocks(ringBlocks),
		afpacket.OptPollTimeout(closePoll),
	)
	if err != nil {
		return nil, fmt.Errorf("open packet ring on %s: %w", ifce.Name, err)
	}
	// The socket is already bound, so a few unfiltered frames may be in the
	// ring by now. The device filters again on its own, so they are dropped.
	if err = ring.SetBPF(filter); err != nil {
		ring.Close()
		return nil, fmt.Errorf("attach filter: %w", err)
	}
	// Only a configured MAC that differs from the interface's own needs
	// promiscuous mode: frames addressed to it are invisible otherwise.
	if err = ring.SetPromiscuous(true); err != nil {
		if !bytes.Equal(netConfig.LocalMAC, ifce.HardwareAddr) {
			ring.Close()
			return nil, fmt.Errorf(
				"promiscuous mode is unavailable on %s (%v), so frames addressed to the configured localMAC %s would never reach us; "+
					"remove localMAC from the config to use the interface address %s",
				ifce.Name, err, netConfig.LocalMAC, ifce.HardwareAddr)
		}
		slog.Warn("promiscuous mode is not supported on this interface, capturing without it",
			"interface", ifce.Name, "reason", err)
	}

	tx, err := newFrameSender(ifce)
	if err != nil {
		ring.Close()
		return nil, err
	}
	return &afpacketSource{ring: ring, tx: tx}, nil
}

// ReadFrame returns the next captured frame. The slice points into the ring
// and is handed back to the kernel on the next call.
func (s *afpacketSource) ReadFrame() ([]byte, error) {
	if s.closed.Load() {
		return nil, s.release()
	}
	frame, _, err := s.ring.ZeroCopyReadPacketData()
	switch {
	case errors.Is(err, afpacket.ErrTimeout):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return frame, nil
}

// release unmaps the ring. Only the reading goroutine may do it: a frame it
// returned earlier points into the mapping.
func (s *afpacketSource) release() error {
	s.ring.Close()
	return io.EOF
}

func (s *afpacketSource) WriteFrame(p []byte) error {
	return s.tx.send([][]byte{p})
}

func (s *afpacketSource) WriteFrames(frames [][]byte) error {
	return s.tx.send(frames)
}

// Close stops the source. A blocked ReadFrame notices within closePoll and
// returns io.EOF.
func (s *afpacketSource) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	return s.tx.close()
}
