// Package iobased provides the implementation of io.ReadWriter
// based data-link layer endpoints.
package iobased

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// Queue length for outbound packet, arriving for read. Overflow
	// causes packet drops.
	defaultOutQueueLen = 1 << 10

	// maxWriteBatch bounds how many outbound packets are handed to a
	// BatchWriter at once.
	maxWriteBatch = 64

	// slowWriteLogThreshold keeps the "slowest write" log quiet while the
	// record is still being set by ordinary, fast writes.
	slowWriteLogThreshold = time.Millisecond
)

// Endpoint implements the interface of stack.LinkEndpoint from io.ReadWriter.
type Endpoint struct {
	*channel.Endpoint

	// rw is the io.ReadWriter for reading and writing packets.
	rw ReadWriter

	// mtu (maximum transmission unit) is the maximum size of a packet.
	mtu uint32

	// once is used to perform the init action once when attaching.
	once sync.Once

	// wg keeps track of running goroutines.
	wg sync.WaitGroup

	// done is closed when the dispatch loop stops, which happens when the
	// underlying source can no longer be read from.
	done chan struct{}

	// dropped counts outbound packets discarded because the queue was full.
	dropped atomic.Uint64
	// slowestWrite is the longest a single write to the source has taken.
	slowestWrite atomic.Int64
}

// TxStats describes how sending has gone since the endpoint was created.
type TxStats struct {
	// Dropped is how many outbound packets were discarded because the source
	// could not keep up with the stack.
	Dropped uint64
	// SlowestWrite is the longest a single write of a batch has taken.
	SlowestWrite time.Duration
}

// TxStats returns the transmit counters.
func (e *Endpoint) TxStats() TxStats {
	return TxStats{
		Dropped:      e.dropped.Load(),
		SlowestWrite: time.Duration(e.slowestWrite.Load()),
	}
}

// WritePackets queues packets for the outbound loop. The stack never waits
// for the source: sending happens on a goroutine of its own.
//
// When the source cannot keep up and the queue is full, the oldest queued
// packets make way for the new ones. For a game the packet that has waited
// longest is the one worth least, and for TCP losing the head of the queue
// is noticed a queue length sooner than losing the tail.
func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	for excess := e.NumQueued() + pkts.Len() - defaultOutQueueLen; excess > 0; excess-- {
		oldest := e.Endpoint.Read()
		if oldest == nil {
			break
		}
		oldest.DecRef()
		e.dropped.Add(1)
	}
	return e.Endpoint.WritePackets(pkts)
}

// New returns stack.LinkEndpoint(.*Endpoint) and error.
func New(rw ReadWriter, mtu uint32, offset int, mac net.HardwareAddr) (*Endpoint, error) {
	if mtu == 0 {
		return nil, errors.New("MTU size is zero")
	}

	if rw == nil {
		return nil, errors.New("RW interface is nil")
	}

	if offset < 0 {
		return nil, errors.New("offset must be non-negative")
	}

	linkAddr, err := tcpip.ParseMACAddress(mac.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse link address: %w", err)
	}

	return &Endpoint{
		Endpoint: channel.New(defaultOutQueueLen, mtu, linkAddr),
		rw:       rw,
		mtu:      mtu,
		done:     make(chan struct{}),
	}, nil
}

// Attach launches the goroutine that reads packets from io.Reader and
// dispatches them via the provided dispatcher.
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.Endpoint.Attach(dispatcher)
	e.once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		e.wg.Add(2)
		go func() {
			e.outboundLoop(ctx)
			e.wg.Done()
		}()
		go func() {
			e.dispatchLoop(cancel)
			e.wg.Done()
		}()
	})
}

func (e *Endpoint) Wait() {
	e.wg.Wait()
}

// Done is closed once the dispatch loop has stopped: the frame source is gone
// and no further inbound traffic will ever be seen.
func (e *Endpoint) Done() <-chan struct{} {
	return e.done
}

// dispatchLoop dispatches packets to upper layer.
func (e *Endpoint) dispatchLoop(cancel context.CancelFunc) {
	// Call cancel() to ensure (*Endpoint).outboundLoop(context.Context) exits
	// gracefully after (*Endpoint).dispatchLoop(context.CancelFunc) returns.
	defer cancel()
	defer close(e.done)

	for {
		data, err := e.rw.Read()
		if err != nil {
			// The source is gone; nothing left to dispatch. Anything other than
			// an orderly close means we lost the capture, which leaves the
			// process running as a silent no-op router unless it is reported.
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				slog.Debug("device closed, dispatch loop stopped")
			} else {
				slog.Error("device read failed, dispatch loop stopped", slog.Any("err", err))
			}
			return
		}

		if len(data) == 0 {
			continue /* filtered out by the device */
		}

		if !e.IsAttached() {
			continue /* unattached, drop packet */
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(data),
		})

		e.InjectInbound(header.EthernetProtocolAll, pkt)

		pkt.DecRef()
	}
}

// outboundLoop reads outbound packets from channel, and then it calls
// writePacket to send those packets back to lower layer.
func (e *Endpoint) outboundLoop(ctx context.Context) {
	bw, batching := e.rw.(BatchWriter)
	if !batching {
		for {
			pkt := e.ReadContext(ctx)
			if pkt == nil {
				break
			}
			e.writePacket(pkt)
		}
		return
	}

	views := make([]*buffer.View, 0, maxWriteBatch)
	frames := make([][]byte, 0, maxWriteBatch)
	var (
		reportedDrops uint64
		lastReport    time.Time
	)
	for {
		pkt := e.ReadContext(ctx)
		if pkt == nil {
			break
		}
		// Take whatever else is already queued, without waiting for more:
		// an idle link still sends every packet immediately, a busy one
		// sends them a batch at a time.
		for pkt != nil {
			view := pkt.ToView()
			pkt.DecRef()
			views = append(views, view)
			frames = append(frames, view.AsSlice())
			if len(frames) == maxWriteBatch {
				break
			}
			pkt = e.Read()
		}

		start := time.Now()
		_ = bw.WriteFrames(frames)
		took := time.Since(start)

		// A write that takes longer than any before it is the first sign of a
		// source that is struggling, well before anything is dropped.
		if int64(took) > e.slowestWrite.Load() {
			e.slowestWrite.Store(int64(took))
			if took >= slowWriteLogThreshold {
				slog.Debug("slowest write to the device so far", "took", took, "frames", len(frames))
			}
		}
		if dropped := e.dropped.Load(); dropped != reportedDrops && start.Sub(lastReport) >= time.Second {
			slog.Warn("device cannot keep up, dropped the oldest queued packets",
				"dropped", dropped-reportedDrops, "total", dropped)
			reportedDrops, lastReport = dropped, start
		}

		for i, view := range views {
			view.Release()
			views[i], frames[i] = nil, nil
		}
		views, frames = views[:0], frames[:0]
	}
}

// writePacket writes outbound packets to the io.Writer.
func (e *Endpoint) writePacket(pkt *stack.PacketBuffer) tcpip.Error {
	defer pkt.DecRef()

	view := pkt.ToView()
	defer view.Release()
	_, err := view.WriteTo(e.rw)
	if err != nil {
		return &tcpip.ErrInvalidEndpointState{}
	}
	return nil
}

// BatchWriter is an optional extension of ReadWriter. When the device
// implements it, the outbound loop sends queued packets in batches.
type BatchWriter interface {
	WriteFrames(frames [][]byte) error
}

type ReadWriter interface {
	io.Writer

	// Read returns the next inbound frame. A nil frame with a nil error means
	// the frame was dropped and reading should continue; a non-nil error
	// terminates the dispatch loop.
	Read() ([]byte, error)
}
