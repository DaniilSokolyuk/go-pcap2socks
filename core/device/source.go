package device

import (
	"io"
	"sync"
)

// FrameSource is the lowest level seam of the device: a bidirectional source of
// layer 2 ethernet frames. The pcap handle is one implementation, MemSource is
// an in-memory one used by tests.
type FrameSource interface {
	// ReadFrame blocks until the next frame is available. The returned slice is
	// only valid until the next call. A nil frame with a nil error means "no
	// frame this time, keep going"; io.EOF means the source is closed.
	ReadFrame() ([]byte, error)

	// WriteFrame sends a single frame. Implementations must not retain p.
	WriteFrame(p []byte) error

	// Close releases the source and unblocks any pending ReadFrame.
	Close() error
}

// BatchWriter is an optional extension of FrameSource for sources that can
// send several frames for the price of one call. The device hands over
// whatever the stack has queued, so under load a batch replaces one system
// call per frame with one per batch.
type BatchWriter interface {
	// WriteFrames sends the frames in order. Implementations must not retain
	// them.
	WriteFrames(frames [][]byte) error
}

// ChecksumOffloader is an optional extension of FrameSource. A source whose
// frames may carry IP and transport checksums that are not valid on their own - the
// kernel merged several packets into one - says so, and the stack then leaves
// them unverified.
type ChecksumOffloader interface {
	RXChecksumOffload() bool
}

// frameSender is how a live source sends a batch of frames in fewer calls than
// one per frame: sendmmsg on Linux, an Npcap send queue on Windows.
type frameSender interface {
	send(frames [][]byte) error
	close() error
}

// MemSource is an in-memory FrameSource. The device side reads with ReadFrame
// and writes with WriteFrame; the opposite side (a test harness acting as the
// wire) injects frames with Inject and consumes them from Outbound.
type MemSource struct {
	inbound   chan []byte
	outbound  chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

var _ FrameSource = (*MemSource)(nil)

// NewMemSource returns a MemSource buffering up to queue frames per direction.
func NewMemSource(queue int) *MemSource {
	if queue <= 0 {
		queue = 256
	}

	return &MemSource{
		inbound:  make(chan []byte, queue),
		outbound: make(chan []byte, queue),
		done:     make(chan struct{}),
	}
}

func (m *MemSource) ReadFrame() ([]byte, error) {
	// A closed source never delivers another frame: checking done first keeps
	// that deterministic, since select would otherwise pick at random when both
	// cases are ready.
	select {
	case <-m.done:
		return nil, io.EOF
	default:
	}

	select {
	case frame := <-m.inbound:
		return frame, nil
	case <-m.done:
		return nil, io.EOF
	}
}

func (m *MemSource) WriteFrame(p []byte) error {
	select {
	case <-m.done:
		return io.ErrClosedPipe
	default:
	}

	frame := make([]byte, len(p))
	copy(frame, p)

	select {
	case m.outbound <- frame:
		return nil
	case <-m.done:
		return io.ErrClosedPipe
	}
}

func (m *MemSource) Close() error {
	m.closeOnce.Do(func() {
		close(m.done)
	})
	return nil
}

// Inject queues a frame to be read by the device. It copies p and drops the
// frame if the source is closed.
func (m *MemSource) Inject(p []byte) {
	select {
	case <-m.done:
		return
	default:
	}

	frame := make([]byte, len(p))
	copy(frame, p)

	select {
	case m.inbound <- frame:
	case <-m.done:
	}
}

// Outbound returns the channel of frames emitted by the device.
func (m *MemSource) Outbound() <-chan []byte {
	return m.outbound
}

// Done is closed when the source is closed.
func (m *MemSource) Done() <-chan struct{} {
	return m.done
}
