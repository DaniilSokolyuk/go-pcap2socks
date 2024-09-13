package core

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/DaniilSokolyuk/go-pcap2socks/tunnel"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/udpnat"

	"github.com/DaniilSokolyuk/go-pcap2socks/core/adapter"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/option"
	"github.com/DaniilSokolyuk/go-pcap2socks/md"
	MM "github.com/DaniilSokolyuk/go-pcap2socks/md"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type Handler interface {
	N.UDPConnectionHandler
	E.Handler
}

type handler struct {
	handle func(adapter.UDPConn)
}

func (h handler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	h.handle(proxyHandler{meta: metadata, conn: conn})
	return nil
}

func (h handler) NewError(ctx context.Context, err error) {
	slog.Error("udp PacketConnection proxy error: ", slog.Any("err", err))
}

func CreateProxyHandler(a func(adapter.UDPConn)) Handler {
	return &handler{
		handle: a,
	}
}

type proxyHandler struct {
	conn N.PacketConn
	meta M.Metadata
}

func (ph proxyHandler) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buffer := buf.With(p)
	destination, err := ph.conn.ReadPacket(buffer)
	if err != nil {
		slog.Error("udp read packet error: ", slog.Any("err", err))
		return
	}
	n = buffer.Len()
	if buffer.Start() > 0 {
		copy(p, buffer.Bytes())
	}
	addr = destination.UDPAddr()
	return
}

func (ph proxyHandler) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	bf := buf.NewSize(len(p))
	common.Must1(bf.Write(p))
	err = ph.conn.WritePacket(bf, M.SocksaddrFromNet(addr).Unwrap())
	if err != nil {
		slog.Error("udp write packet error: ", slog.Any("err", err))
		return 0, err
	}

	return len(p), nil
}

func (ph proxyHandler) Close() error {
	return ph.conn.Close()
}

func (ph proxyHandler) LocalAddr() net.Addr {
	return ph.conn.LocalAddr()
}

func (ph proxyHandler) SetDeadline(t time.Time) error {
	return ph.conn.SetDeadline(t)
}

func (ph proxyHandler) SetReadDeadline(t time.Time) error {
	return ph.conn.SetReadDeadline(t)
}

func (ph proxyHandler) SetWriteDeadline(t time.Time) error {
	return ph.conn.SetWriteDeadline(t)
}

func (ph proxyHandler) MD() *metadata.Metadata {
	mh := &MM.Metadata{
		Network: MM.UDP,
		SrcIP:   net.IP(ph.meta.Source.Addr.AsSlice()),
		SrcPort: ph.meta.Source.Port,
		DstIP:   net.IP(ph.meta.Destination.Addr.AsSlice()),
		DstPort: ph.meta.Destination.Port,
	}

	return mh
}

func withUDPNatHandler(handle func(adapter.UDPConn)) option.Option {
	return func(s *stack.Stack) error {
		udpForwarder := NewUDPForwarder(context.Background(), s, CreateProxyHandler(handle), int64(tunnel.UdpSessionTimeout.Seconds()))
		s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
		return nil
	}
}

type UDPForwarder struct {
	ctx    context.Context
	stack  *stack.Stack
	udpNat *udpnat.Service[netip.AddrPort]

	// cache
	cacheProto tcpip.NetworkProtocolNumber
	cacheID    stack.TransportEndpointID
}

func NewUDPForwarder(ctx context.Context, stack *stack.Stack, handler Handler, udpTimeout int64) *UDPForwarder {
	return &UDPForwarder{
		ctx:    ctx,
		stack:  stack,
		udpNat: udpnat.New[netip.AddrPort](udpTimeout, handler),
	}
}

func (f *UDPForwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	var upstreamMetadata M.Metadata
	upstreamMetadata.Source = M.SocksaddrFrom(AddrFromAddress(id.RemoteAddress), id.RemotePort)
	upstreamMetadata.Destination = M.SocksaddrFrom(AddrFromAddress(id.LocalAddress), id.LocalPort)
	if upstreamMetadata.Source.IsIPv4() {
		f.cacheProto = header.IPv4ProtocolNumber
	} else {
		f.cacheProto = header.IPv6ProtocolNumber
	}
	gBuffer := pkt.Data().ToBuffer()
	sBuffer := buf.NewSize(int(gBuffer.Size()))
	gBuffer.Apply(func(view *buffer.View) {
		sBuffer.Write(view.AsSlice())
	})
	f.cacheID = id
	f.udpNat.NewPacket(
		f.ctx,
		upstreamMetadata.Source.AddrPort(),
		sBuffer,
		upstreamMetadata,
		f.newUDPConn,
	)
	return true
}

func (f *UDPForwarder) newUDPConn(natConn N.PacketConn) N.PacketWriter {
	return &UDPBackWriter{
		stack:         f.stack,
		source:        f.cacheID.RemoteAddress,
		sourcePort:    f.cacheID.RemotePort,
		sourceNetwork: f.cacheProto,
	}
}

type UDPBackWriter struct {
	access        sync.Mutex
	stack         *stack.Stack
	source        tcpip.Address
	sourcePort    uint16
	sourceNetwork tcpip.NetworkProtocolNumber
}

func (w *UDPBackWriter) WritePacket(packetBuffer *buf.Buffer, destination M.Socksaddr) error {
	if !destination.IsIP() {
		return E.Cause(os.ErrInvalid, "invalid destination")
	} else if destination.IsIPv4() && w.sourceNetwork == header.IPv6ProtocolNumber {
		destination = M.SocksaddrFrom(netip.AddrFrom16(destination.Addr.As16()), destination.Port)
	} else if destination.IsIPv6() && (w.sourceNetwork == header.IPv4ProtocolNumber) {
		return E.New("send IPv6 packet to IPv4 connection")
	}

	defer packetBuffer.Release()

	route, err := w.stack.FindRoute(
		NicID,
		AddressFromAddr(destination.Addr),
		w.source,
		w.sourceNetwork,
		false,
	)
	if err != nil {
		return fmt.Errorf("find route: %s", err)
	}
	defer route.Release()

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + int(route.MaxHeaderLength()),
		Payload:            buffer.MakeWithData(packetBuffer.Bytes()),
	})
	defer packet.DecRef()

	packet.TransportProtocolNumber = header.UDPProtocolNumber
	udpHdr := header.UDP(packet.TransportHeader().Push(header.UDPMinimumSize))
	pLen := uint16(packet.Size())
	udpHdr.Encode(&header.UDPFields{
		SrcPort: destination.Port,
		DstPort: w.sourcePort,
		Length:  pLen,
	})

	if route.RequiresTXTransportChecksum() && w.sourceNetwork == header.IPv6ProtocolNumber {
		xsum := udpHdr.CalculateChecksum(checksum.Combine(
			route.PseudoHeaderChecksum(header.UDPProtocolNumber, pLen),
			packet.Data().Checksum(),
		))
		if xsum != math.MaxUint16 {
			xsum = ^xsum
		}
		udpHdr.SetChecksum(xsum)
	}

	err = route.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.UDPProtocolNumber,
		TTL:      route.DefaultTTL(),
		TOS:      0,
	}, packet)

	if err != nil {
		route.Stats().UDP.PacketSendErrors.Increment()
		return fmt.Errorf("write packet: %s", err)
	}

	route.Stats().UDP.PacketsSent.Increment()
	return nil
}

func AddrFromAddress(address tcpip.Address) netip.Addr {
	if address.Len() == 16 {
		return netip.AddrFrom16(address.As16())
	} else {
		return netip.AddrFrom4(address.As4())
	}
}

func AddressFromAddr(destination netip.Addr) tcpip.Address {
	if destination.Is6() {
		return tcpip.AddrFrom16(destination.As16())
	} else {
		return tcpip.AddrFrom4(destination.As4())
	}
}
