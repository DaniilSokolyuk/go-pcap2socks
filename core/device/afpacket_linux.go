package device

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket/afpacket"
	"golang.org/x/sys/unix"
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

	// mu guards reading: once a read has started, only the reader may give
	// the ring back, because a frame it returned points into the mapping.
	mu          sync.Mutex
	reading     bool
	releaseOnce sync.Once
}

var (
	_ FrameSource = (*afpacketSource)(nil)
	_ BatchWriter = (*afpacketSource)(nil)
)

const (
	// What a frame needs in its slot besides the IP packet: the ethernet
	// header, a VLAN tag, and the ring's own header and alignment.
	ringSlotOverhead = 256
	ringMinFrameSize = 2048
	// A multiple of every page size in use (4K, 16K, 64K) and of any frame
	// size below, which are powers of two.
	ringBlockSize = 1 << 20
	// How much memory the ring is given.
	ringBytes = 4 << 20

	// How long a read waits before checking whether the source was closed.
	closePoll = 100 * time.Millisecond
)

// ringFrameSize is the slot size for an interface MTU: a power of two with
// room for the largest frame, so a jumbo MTU is not silently truncated.
func ringFrameSize(mtu uint32) int {
	size := ringMinFrameSize
	for size < int(mtu)+ringSlotOverhead && size < ringBlockSize {
		size <<= 1
	}
	return size
}

func newAFPacketSource(ifce net.Interface, netConfig *NetworkConfig) (*afpacketSource, error) {
	filter, err := CaptureFilter(netConfig)
	if err != nil {
		return nil, err
	}

	ring, err := afpacket.NewTPacket(
		afpacket.OptInterface(ifce.Name),
		afpacket.SocketRaw,
		afpacket.TPacketVersion2,
		afpacket.OptFrameSize(ringFrameSize(netConfig.MTU)),
		afpacket.OptBlockSize(ringBlockSize),
		afpacket.OptNumBlocks(ringBytes/ringBlockSize),
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
	ignoreOutgoing(ring)

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

// ignoreOutgoing stops the kernel from offering our own transmitted frames to
// the capture socket. Without it every frame we send is cloned and run
// through the filter just to be rejected, on the sending path. gopacket does
// not expose the option or the descriptor, so the descriptor is read from its
// unexported field; if that ever stops working the filter still does the job.
// Linux 4.20+.
func ignoreOutgoing(ring *afpacket.TPacket) {
	field := reflect.ValueOf(ring).Elem().FieldByName("fd")
	if !field.IsValid() || !field.CanInt() || field.Int() < 0 {
		return
	}
	_ = unix.SetsockoptInt(int(field.Int()), unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1)
}

// ReadFrame returns the next captured frame. The slice points into the ring
// and is handed back to the kernel on the next call.
func (s *afpacketSource) ReadFrame() ([]byte, error) {
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		s.release()
		return nil, io.EOF
	}
	s.reading = true
	s.mu.Unlock()

	frame, _, err := s.ring.ZeroCopyReadPacketData()
	switch {
	case errors.Is(err, afpacket.ErrTimeout):
		return nil, nil
	case err != nil:
		// The dispatch loop stops on an error and never calls again, so
		// this is the last chance to give the ring back.
		s.release()
		return nil, err
	}
	return frame, nil
}

// release unmaps the ring and closes its socket, once.
func (s *afpacketSource) release() {
	s.releaseOnce.Do(s.ring.Close)
}

func (s *afpacketSource) WriteFrame(p []byte) error {
	return s.tx.send([][]byte{p})
}

func (s *afpacketSource) WriteFrames(frames [][]byte) error {
	return s.tx.send(frames)
}

// Close stops the source. A blocked ReadFrame notices within closePoll and
// returns io.EOF, and gives the ring back itself; if no read ever started
// there is nobody else to do it.
func (s *afpacketSource) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	s.mu.Lock()
	reading := s.reading
	s.mu.Unlock()
	if !reading {
		s.release()
	}
	return s.tx.close()
}
