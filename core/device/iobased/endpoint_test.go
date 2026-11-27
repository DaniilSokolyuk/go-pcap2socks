package iobased

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// idleDevice never produces a frame and is never written to: the endpoint is
// not attached in these tests, so nothing drains its queue.
type idleDevice struct{}

func (idleDevice) Read() ([]byte, error)      { return nil, io.EOF }
func (idleDevice) WriteFrames([][]byte) error { return nil }

func queuePacket(t *testing.T, ep *Endpoint, id uint32) {
	t.Helper()
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, id)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(payload)})
	var list stack.PacketBufferList
	list.PushBack(pkt)
	n, err := ep.WritePackets(list)
	list.Reset()
	require.Nil(t, err)
	require.Equal(t, 1, n)
}

func nextQueued(t *testing.T, ep *Endpoint) uint32 {
	t.Helper()
	pkt := ep.Read()
	require.NotNil(t, pkt)
	defer pkt.DecRef()
	view := pkt.ToView()
	defer view.Release()
	return binary.BigEndian.Uint32(view.AsSlice())
}

// A full queue makes room by discarding its oldest packets, so the newest
// ones are always the ones kept.
func TestOverflowDropsOldest(t *testing.T) {
	ep, err := New(idleDevice{}, 1500, 0, net.HardwareAddr{2, 0, 0, 0, 0, 1})
	require.NoError(t, err)

	const extra = 10
	for id := uint32(0); id < defaultOutQueueLen+extra; id++ {
		queuePacket(t, ep, id)
	}

	require.Equal(t, uint64(extra), ep.TxStats().Dropped)
	require.Equal(t, defaultOutQueueLen, ep.NumQueued())
	require.Equal(t, uint32(extra), nextQueued(t, ep), "the oldest survivor is the first one that still fitted")

	// Order among the survivors is untouched.
	require.Equal(t, uint32(extra+1), nextQueued(t, ep))
}

func TestNoDropsBelowCapacity(t *testing.T) {
	ep, err := New(idleDevice{}, 1500, 0, net.HardwareAddr{2, 0, 0, 0, 0, 1})
	require.NoError(t, err)

	for id := uint32(0); id < defaultOutQueueLen; id++ {
		queuePacket(t, ep, id)
	}
	require.Zero(t, ep.TxStats().Dropped)
	require.Equal(t, uint32(0), nextQueued(t, ep))
}

// Writers race each other for the last free slots. Whatever the interleaving,
// every packet is either in the queue or counted as dropped.
func TestConcurrentWritersAccountForEveryPacket(t *testing.T) {
	ep, err := New(idleDevice{}, 1500, 0, net.HardwareAddr{2, 0, 0, 0, 0, 1})
	require.NoError(t, err)

	const writers, each = 8, 400 // 3200 packets into a queue of 1024
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				payload := []byte{0, 0, 0, 0}
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(payload)})
				var list stack.PacketBufferList
				list.PushBack(pkt)
				_, _ = ep.WritePackets(list)
				list.Reset()
			}
		}()
	}
	wg.Wait()

	require.Equal(t, defaultOutQueueLen, ep.NumQueued())
	require.Equal(t, uint64(writers*each-defaultOutQueueLen), ep.TxStats().Dropped)
}
