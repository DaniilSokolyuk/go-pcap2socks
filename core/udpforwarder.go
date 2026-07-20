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

	"github.com/DaniilSokolyuk/go-pcap2socks/core/adapter"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/option"
	"github.com/DaniilSokolyuk/go-pcap2socks/md"
	MM "github.com/DaniilSokolyuk/go-pcap2socks/md"
	"github.com/DaniilSokolyuk/go-pcap2socks/tunnel"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	udpnat "github.com/sagernet/sing/common/udpnat2"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type handler struct {
	handle func(adapter.UDPConn)
}

func (h handler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.handle(proxyHandler{
		conn:        conn,
		source:      source,
		destination: destination,
	})
	if onClose != nil {
		onClose(nil)
	}
}

func CreateProxyHandler(a func(adapter.UDPConn)) N.UDPConnectionHandlerEx {
	return handler{handle: a}
}

type proxyHandler struct {
	conn        N.PacketConn
	source      M.Socksaddr
	destination M.Socksaddr
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
	return &MM.Metadata{
		Network: MM.UDP,
		SrcIP:   net.IP(ph.source.Addr.AsSlice()),
		SrcPort: ph.source.Port,
		DstIP:   net.IP(ph.destination.Addr.AsSlice()),
		DstPort: ph.destination.Port,
	}
}

func withUDPNatHandler(handle func(adapter.UDPConn)) option.Option {
	return func(s *stack.Stack) error {
		udpForwarder := NewUDPForwarder(context.Background(), s, CreateProxyHandler(handle), tunnel.UdpSessionTimeout)
		s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
		return nil
	}
}

type UDPForwarder struct {
	ctx    context.Context
	stack  *stack.Stack
	udpNat *udpnat.Service
}

func NewUDPForwarder(ctx context.Context, stack *stack.Stack, handler N.UDPConnectionHandlerEx, udpTimeout time.Duration) *UDPForwarder {
	f := &UDPForwarder{
		ctx:   ctx,
		stack: stack,
	}
	f.udpNat = udpnat.New(handler, f.prepare, udpTimeout, true)
	return f
}

func (f *UDPForwarder) prepare(source M.Socksaddr, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	proto := header.IPv6ProtocolNumber
	if source.IsIPv4() {
		proto = header.IPv4ProtocolNumber
	}
	writer := &UDPBackWriter{
		stack:         f.stack,
		source:        AddressFromAddr(source.Addr),
		sourcePort:    source.Port,
		sourceNetwork: proto,
	}
	return true, f.ctx, writer, nil
}

func (f *UDPForwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	source := M.SocksaddrFrom(AddrFromAddress(id.RemoteAddress), id.RemotePort)
	destination := M.SocksaddrFrom(AddrFromAddress(id.LocalAddress), id.LocalPort)
	gBuffer := pkt.Data().ToBuffer()
	bufferSlices := make([][]byte, 0, 1)
	gBuffer.Apply(func(view *buffer.View) {
		bufferSlices = append(bufferSlices, view.AsSlice())
	})
	f.udpNat.NewPacket(bufferSlices, source, destination, nil)
	return true
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
