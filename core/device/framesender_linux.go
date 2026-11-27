package device

import (
	"fmt"
	"net"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// packetSender sends ethernet frames through a packet socket with sendmmsg:
// one system call for a whole batch. gopacket's afpacket can only send a frame
// per call, and that was half the CPU time of a download.
type packetSender struct {
	mu   sync.Mutex
	fd   int
	msgs []mmsghdr
	iovs []unix.Iovec
}

// mmsghdr mirrors struct mmsghdr. Go pads it to the alignment of Msghdr,
// which matches the C layout on both 32 and 64 bit.
type mmsghdr struct {
	hdr unix.Msghdr
	n   uint32
}

const senderBatch = 64

func newFrameSender(ifce net.Interface) (frameSender, error) {
	// Protocol 0: the socket is never handed a received frame.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("packet socket: %w", err)
	}
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: ifce.Index}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind packet socket to %s: %w", ifce.Name, err)
	}
	return &packetSender{
		fd:   fd,
		msgs: make([]mmsghdr, senderBatch),
		iovs: make([]unix.Iovec, senderBatch),
	}, nil
}

func (s *packetSender) send(frames [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for len(frames) > 0 {
		n := min(len(frames), senderBatch)
		for i, frame := range frames[:n] {
			s.msgs[i] = mmsghdr{}
			s.iovs[i] = unix.Iovec{}
			if len(frame) > 0 {
				s.iovs[i].Base = &frame[0]
				s.iovs[i].SetLen(len(frame))
			}
			s.msgs[i].hdr.Iov = &s.iovs[i]
			s.msgs[i].hdr.SetIovlen(1)
		}

		// sendmmsg reports an error only when the very first message fails;
		// otherwise it returns how many went out and the rest are retried.
		sent, _, errno := unix.Syscall6(unix.SYS_SENDMMSG,
			uintptr(s.fd), uintptr(unsafe.Pointer(&s.msgs[0])), uintptr(n), 0, 0, 0)
		switch {
		case errno == unix.EINTR || errno == unix.EAGAIN:
			continue
		case errno == unix.ENOBUFS || errno == unix.EMSGSIZE || errno == unix.EINVAL:
			// This frame cannot be sent: the device queue is full, or the
			// frame is oversized or shorter than an ethernet header. Drop it,
			// as the wire would, and carry on with the rest.
			frames = frames[1:]
			continue
		case errno != 0:
			return fmt.Errorf("sendmmsg: %w", errno)
		}
		frames = frames[sent:]
	}
	return nil
}

func (s *packetSender) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return unix.Close(s.fd)
}
