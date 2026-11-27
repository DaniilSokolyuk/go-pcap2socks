package device

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// afpacketSource is the FrameSource for Linux. It talks to the kernel
// directly, without libpcap and so without cgo: one packet socket to capture
// and packetSender to transmit.
//
// Capture is recvmmsg into buffers that hold 64KB, not a memory mapped ring
// with slots the size of the MTU, and that is the point. A NIC with receive
// offload on, which is every NIC by default, hands the kernel's taps TCP
// segments already merged into packets of up to 64KB. A ring slot of 2KB, or
// libpcap with a snap length of 1600, truncates every one of them, the stack
// throws the remains away, and a bulk upload from the console drops to a few
// Mbit/s with nothing in the log. Read whole, the same merged packets are an
// advantage: one large segment for the stack instead of forty small ones.
type afpacketSource struct {
	fd     int
	tx     frameSender
	closed atomic.Bool

	// A batch of received frames, and the one to hand out next.
	msgs    []mmsghdr
	iovs    []unix.Iovec
	buffers [][]byte
	count   int
	next    int

	lastStats time.Time

	// mu guards reading: once a read has started, only the reader may close
	// the socket, because it may be inside a system call on it.
	mu          sync.Mutex
	reading     bool
	releaseOnce sync.Once
}

var (
	_ FrameSource       = (*afpacketSource)(nil)
	_ BatchWriter       = (*afpacketSource)(nil)
	_ ChecksumOffloader = (*afpacketSource)(nil)
)

const (
	// The largest packet receive offload produces, plus the ethernet header
	// and a VLAN tag.
	captureFrameSize = 1<<16 + 32
	// Frames taken per system call.
	captureBatch = 32
	// The socket's receive queue. The default holds three merged packets.
	captureSocketBuffer = 8 << 20

	// How long a read waits before checking whether the source was closed.
	closePollMillis = 100
	// How often dropped frames are looked for.
	captureStatsInterval = time.Second
)

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func newAFPacketSource(ifce net.Interface, netConfig *NetworkConfig) (_ *afpacketSource, err error) {
	filter, err := CaptureFilter(netConfig)
	if err != nil {
		return nil, err
	}

	// Protocol 0 keeps the socket deaf until it is bound below, so nothing
	// unfiltered is queued while it is being set up.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("packet socket: %w", err)
	}
	defer func() {
		if err != nil {
			unix.Close(fd)
		}
	}()

	program := make([]unix.SockFilter, len(filter))
	for i, ins := range filter {
		program[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(program)), Filter: &program[0]}
	if err = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog); err != nil {
		return nil, fmt.Errorf("attach filter: %w", err)
	}

	// Everything we capture comes from another machine. Without this, every
	// frame we send is cloned and run through the filter just to be rejected,
	// on the sending path. Linux 4.20+; older kernels do that extra work.
	_ = unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1)

	// The forced variant ignores net.core.rmem_max, which is far too small
	// for this; it needs CAP_NET_ADMIN, which capturing needs anyway.
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, captureSocketBuffer) != nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, captureSocketBuffer)
	}

	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifce.Index}); err != nil {
		return nil, fmt.Errorf("bind to %s: %w", ifce.Name, err)
	}

	// Only a configured MAC that differs from the interface's own needs
	// promiscuous mode: frames addressed to it are invisible otherwise.
	membership := unix.PacketMreq{Ifindex: int32(ifce.Index), Type: unix.PACKET_MR_PROMISC}
	if perr := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &membership); perr != nil {
		if !bytes.Equal(netConfig.LocalMAC, ifce.HardwareAddr) {
			return nil, fmt.Errorf(
				"promiscuous mode is unavailable on %s (%v), so frames addressed to the configured localMAC %s would never reach us; "+
					"remove localMAC from the config to use the interface address %s",
				ifce.Name, perr, netConfig.LocalMAC, ifce.HardwareAddr)
		}
		slog.Warn("promiscuous mode is not supported on this interface, capturing without it",
			"interface", ifce.Name, "reason", perr)
	}

	tx, err := newFrameSender(ifce)
	if err != nil {
		return nil, err
	}

	s := &afpacketSource{
		fd:        fd,
		tx:        tx,
		msgs:      make([]mmsghdr, captureBatch),
		iovs:      make([]unix.Iovec, captureBatch),
		buffers:   make([][]byte, captureBatch),
		lastStats: time.Now(),
	}
	for i := range s.buffers {
		s.buffers[i] = make([]byte, captureFrameSize)
		s.iovs[i].Base = &s.buffers[i][0]
		s.iovs[i].SetLen(captureFrameSize)
		s.msgs[i].hdr.Iov = &s.iovs[i]
		s.msgs[i].hdr.SetIovlen(1)
	}
	return s, nil
}

// RXChecksumOffload reports that transport checksums of captured packets must
// not be verified. A packet merged by receive offload carries the checksum of
// a packet that no longer exists; the kernel verified the originals before
// merging them.
func (s *afpacketSource) RXChecksumOffload() bool { return true }

// ReadFrame returns the next captured frame. The slice is only valid until the
// next call.
func (s *afpacketSource) ReadFrame() ([]byte, error) {
	for s.next < s.count {
		i := s.next
		s.next++
		// A frame larger than the buffer cannot happen at 64KB, but a
		// truncated one must never reach the stack as if it were whole.
		if s.msgs[i].hdr.Flags&unix.MSG_TRUNC != 0 {
			continue
		}
		return s.buffers[i][:s.msgs[i].n], nil
	}

	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		s.release()
		return nil, io.EOF
	}
	s.reading = true
	s.mu.Unlock()

	fds := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}
	ready, err := unix.Poll(fds, closePollMillis)
	switch {
	case err == unix.EINTR || (err == nil && ready == 0):
		s.reportDrops()
		return nil, nil
	case err != nil:
		s.release()
		return nil, fmt.Errorf("poll capture socket: %w", err)
	case fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 && fds[0].Revents&unix.POLLIN == 0:
		// The interface went down or away.
		s.release()
		return nil, errors.New("capture socket failed")
	}

	n, _, errno := unix.Syscall6(unix.SYS_RECVMMSG,
		uintptr(s.fd), uintptr(unsafe.Pointer(&s.msgs[0])), uintptr(len(s.msgs)), unix.MSG_DONTWAIT, 0, 0)
	switch {
	case errno == unix.EINTR || errno == unix.EAGAIN:
		return nil, nil
	case errno == unix.ENETDOWN:
		// Reported once when the interface goes down; frames follow again
		// when it comes back.
		return nil, nil
	case errno != 0:
		s.release()
		return nil, fmt.Errorf("recvmmsg: %w", errno)
	}
	s.count, s.next = int(n), 0
	s.reportDrops()
	return nil, nil
}

// reportDrops logs frames the kernel discarded because the socket's queue was
// full: the engine is not reading fast enough, and nothing else would say so.
func (s *afpacketSource) reportDrops() {
	now := time.Now()
	if now.Sub(s.lastStats) < captureStatsInterval {
		return
	}
	s.lastStats = now
	// Reading the counters resets them.
	stats, err := unix.GetsockoptTpacketStats(s.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err == nil && stats.Drops > 0 {
		slog.Warn("capture cannot keep up, the kernel dropped frames",
			"dropped", stats.Drops, "received", stats.Packets)
	}
}

// release closes the capture socket, once.
func (s *afpacketSource) release() {
	s.releaseOnce.Do(func() { _ = unix.Close(s.fd) })
}

func (s *afpacketSource) WriteFrame(p []byte) error {
	return s.tx.send([][]byte{p})
}

func (s *afpacketSource) WriteFrames(frames [][]byte) error {
	return s.tx.send(frames)
}

// Close stops the source. A blocked ReadFrame notices within closePollMillis,
// returns io.EOF and closes the socket itself; if no read ever started there
// is nobody else to do it.
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
