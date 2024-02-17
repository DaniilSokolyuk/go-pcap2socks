// Package iobased provides the implementation of io.ReadWriter
// based data-link layer endpoints.
package iobased

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

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

// dispatchLoop dispatches packets to upper layer.
func (e *Endpoint) dispatchLoop(cancel context.CancelFunc) {
	// Call cancel() to ensure (*Endpoint).outboundLoop(context.Context) exits
	// gracefully after (*Endpoint).dispatchLoop(context.CancelFunc) returns.
	defer cancel()

	mtu := int(e.mtu)

	for {
		data := e.rw.Read()
		if len(data) == 0 {
			continue
		}

		if len(data) > mtu {
			continue
		}

		if !e.IsAttached() {
			continue /* unattached, drop packet */
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload:           buffer.MakeWithData(data),
			IsForwardedPacket: true,
		})

		e.InjectInbound(header.EthernetProtocolAll, pkt)

		pkt.DecRef()
	}
}

// outboundLoop reads outbound packets from channel, and then it calls
// writePacket to send those packets back to lower layer.
func (e *Endpoint) outboundLoop(ctx context.Context) {
	for {
		pkt := e.ReadContext(ctx)
		if pkt.IsNil() {
			break
		}
		e.writePacket(pkt)
	}
}

// writePacket writes outbound packets to the io.Writer.
func (e *Endpoint) writePacket(pkt stack.PacketBufferPtr) tcpip.Error {
	defer pkt.DecRef()

	view := pkt.ToView()
	defer view.Release()
	_, err := view.WriteTo(e.rw)
	if err != nil {
		return &tcpip.ErrInvalidEndpointState{}
	}
	return nil
}

type ReadWriter interface {
	io.Writer
	Read() []byte
}
