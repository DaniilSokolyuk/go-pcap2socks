package e2e

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// serialisation is how long a frame of n bytes takes to clock onto a link of
// the given bit rate.
func serialisation(n int, rate int64) time.Duration {
	return time.Duration(float64(n) * 8 / float64(rate) * float64(time.Second))
}

// Link describes the emulated wire between the console and the engine.
//
// The zero value is the plain in-memory segment every functional test uses:
// no delay, no loss, frames handed over inline.
type Link struct {
	// Delay is the one-way propagation delay applied in each direction, so a
	// connection sees a round trip of roughly twice this.
	Delay time.Duration

	// Loss is the probability that an IPv4 frame is dropped, per direction.
	// ARP is never dropped: address resolution is setup, not the thing under
	// measurement, and losing it only adds resolution retries to the numbers.
	Loss float64

	// Rate, when set, is the bottleneck bandwidth in bits per second. Frames
	// serialise at that rate, so a busy sender builds a real queue and
	// anything sharing the wire waits behind it. Without a rate the wire has
	// infinite bandwidth and latency under load cannot be observed at all.
	Rate int64

	// QueueDepth is how many frames the bottleneck buffers before tail
	// dropping. It only applies when Rate is set; the default stands in for a
	// consumer access point and is deep enough to bufferbloat, which is the
	// point.
	QueueDepth int

	// Seed makes the drop pattern reproducible, so two stack configurations
	// are compared against the same sequence of losses.
	Seed int64
}

const defaultQueueDepth = 128

// active reports whether the link needs a queue and a pump goroutine. Loss
// alone does not: it is applied inline on send. The zero value is the plain
// segment functional tests run on, delivered inline.
func (l Link) active() bool { return l.Delay > 0 || l.Rate > 0 }

func (l Link) queueDepth() int {
	if l.Rate <= 0 {
		// No bottleneck: the queue only has to hold the bandwidth-delay
		// product, and the producer blocks rather than drops when it fills,
		// so nothing is silently attributed to Link.Loss.
		return 8192
	}
	if l.QueueDepth > 0 {
		return l.QueueDepth
	}
	return defaultQueueDepth
}

// wireLine is one direction of the emulated wire: drop some frames, hand the
// rest over Delay later, in order.
type wireLine struct {
	link    Link
	deliver func([]byte)
	rng     *rand.Rand

	q    chan pendingFrame
	done chan struct{}
	wg   sync.WaitGroup

	// tailDrops counts frames the bottleneck queue had no room for. Those are
	// congestion, not the configured Loss, and conflating the two would hide
	// the thing a deep queue is being blamed for.
	tailDrops atomic.Uint64
}

type pendingFrame struct {
	arrived time.Time
	frame   []byte
}

// startLine builds a direction. deliver is called from the line's own
// goroutine when the link delays, and from the caller's when it does not.
func startLine(link Link, seed int64, deliver func([]byte)) *wireLine {
	w := &wireLine{
		link:    link,
		deliver: deliver,
		rng:     rand.New(rand.NewSource(seed)),
		done:    make(chan struct{}),
	}

	if !link.active() {
		return w
	}

	w.q = make(chan pendingFrame, link.queueDepth())
	w.wg.Add(1)
	go w.run()

	return w
}

// send offers a frame to the wire. It must be called from a single producer
// goroutine: the drop decision draws from an unsynchronised PRNG, which is
// what keeps a given Seed reproducible.
func (w *wireLine) send(frame []byte) {
	if w.drop(frame) {
		return
	}

	if w.q == nil {
		w.deliver(frame)
		return
	}

	// The frame outlives the caller's buffer once it sits in the queue: the
	// client side hands us a view it releases straight after.
	queued := make([]byte, len(frame))
	copy(queued, frame)

	pending := pendingFrame{arrived: time.Now(), frame: queued}

	if w.link.Rate <= 0 {
		// No bottleneck to overflow: block instead, so a slow consumer shows
		// up as backpressure rather than as invented loss.
		select {
		case w.q <- pending:
		case <-w.done:
		}
		return
	}

	select {
	case w.q <- pending:
	case <-w.done:
	default:
		w.tailDrops.Add(1)
	}
}

func (w *wireLine) drop(frame []byte) bool {
	if w.link.Loss <= 0 {
		return false
	}
	if len(frame) < header.EthernetMinimumSize {
		return false
	}
	if header.Ethernet(frame).Type() != header.IPv4ProtocolNumber {
		return false
	}

	return w.rng.Float64() < w.link.Loss
}

// run serialises frames onto the wire and delivers each one once it has been
// clocked out and propagated. Draining a single queue in order is what keeps
// the emulated wire from reordering.
func (w *wireLine) run() {
	defer w.wg.Done()

	// When the wire finishes clocking out whatever is currently on it. A frame
	// that arrives while the wire is busy waits, which is what builds a queue
	// and what makes latency under load measurable.
	var idleAt time.Time

	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	if !timer.Stop() {
		<-timer.C
	}

	for {
		select {
		case p := <-w.q:
			start := p.arrived
			if w.link.Rate > 0 {
				if idleAt.After(start) {
					start = idleAt
				}
				idleAt = start.Add(serialisation(len(p.frame), w.link.Rate))
				start = idleAt
			}

			if wait := time.Until(start.Add(w.link.Delay)); wait > 0 {
				timer.Reset(wait)
				select {
				case <-timer.C:
				case <-w.done:
					if !timer.Stop() {
						<-timer.C
					}
					return
				}
			}
			w.deliver(p.frame)
		case <-w.done:
			return
		}
	}
}

// stop shuts the direction down. Producers must already have stopped, so that
// nothing calls send afterwards.
func (w *wireLine) stop() {
	close(w.done)
	w.wg.Wait()
}
