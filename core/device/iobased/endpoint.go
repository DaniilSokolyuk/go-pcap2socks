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

	// icmpSender is used to send ICMP messages for MTU discovery
	icmpSender ICMPSender
}

// ICMPSender is an interface for sending ICMP messages
type ICMPSender interface {
	SendICMPFragmentationNeeded(srcIP, dstIP []byte, mtu uint32, originalPacket []byte) error
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
		Endpoint:   channel.New(defaultOutQueueLen, mtu, linkAddr),
		rw:         rw,
		mtu:        mtu,
		icmpSender: nil, // Will be set later via SetICMPSender
	}, nil
}

// SetICMPSender sets the ICMP sender for this endpoint.
func (e *Endpoint) SetICMPSender(sender ICMPSender) {
	e.icmpSender = sender
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
			// Packet is too large for MTU - send ICMP Fragmentation Needed
			// Note: data includes Ethernet header (14 bytes), skip it to get IP packet
			const ethernetHeaderSize = 14
			if e.icmpSender != nil && len(data) >= ethernetHeaderSize+header.IPv4MinimumSize {
				// Skip Ethernet header to get IP packet
				ipPacket := data[ethernetHeaderSize:]
				ipHeader := header.IPv4(ipPacket)
				if ipHeader.IsValid(len(ipPacket)) {
					srcAddr := ipHeader.SourceAddress()
					dstAddr := ipHeader.DestinationAddress()
					srcIP := srcAddr.As4()
					dstIP := dstAddr.As4()

					// Send ICMP Fragmentation Needed to inform sender about MTU
					// Subtract Ethernet header from MTU since ICMP MTU is at IP level
					ipMTU := e.mtu - ethernetHeaderSize
					err := e.icmpSender.SendICMPFragmentationNeeded(srcIP[:], dstIP[:], ipMTU, ipPacket)
					if err != nil {
						slog.Debug("[MTU] Failed to send ICMP Fragmentation Needed", "error", err)
					} else {
						slog.Debug("[MTU] Packet too large, sent ICMP Fragmentation Needed",
							"packet_size", len(data),
							"mtu", e.mtu,
							"ip_mtu", ipMTU,
							"src", srcIP,
							"dst", dstIP,
							"df_flag", (ipHeader.Flags()&header.IPv4FlagDontFragment) != 0)
					}
				}
			}

			slog.Debug("[MTU] Dropping packet larger than MTU", "packet_size", len(data), "mtu", e.mtu)
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
		if pkt == nil {
			break
		}
		e.writePacket(pkt)
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

type ReadWriter interface {
	io.Writer
	Read() []byte
}
