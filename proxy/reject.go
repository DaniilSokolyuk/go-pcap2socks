package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"time"

	M "github.com/DaniilSokolyuk/go-pcap2socks/md"
)

var _ Proxy = (*Reject)(nil)

type Reject struct {
	*Base
}

func NewReject() *Reject {
	return &Reject{
		Base: &Base{
			mode: ModeReject,
		},
	}
}

func (r *Reject) DialContext(_ context.Context, metadata *M.Metadata) (net.Conn, error) {
	slog.Info("[REJECT TCP]", "source", metadata.SourceAddress(), "dest", metadata.DestinationAddress())
	return &nopConn{}, nil
}

func (r *Reject) DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	slog.Info("[REJECT UDP]", "source", metadata.SourceAddress(), "dest", metadata.DestinationAddress())
	return &nopPacketConn{}, nil
}

type nopConn struct{}

func (rw *nopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (rw *nopConn) Write([]byte) (int, error)        { return 0, io.EOF }
func (rw *nopConn) Close() error                     { return nil }
func (rw *nopConn) LocalAddr() net.Addr              { return nil }
func (rw *nopConn) RemoteAddr() net.Addr             { return nil }
func (rw *nopConn) SetDeadline(time.Time) error      { return nil }
func (rw *nopConn) SetReadDeadline(time.Time) error  { return nil }
func (rw *nopConn) SetWriteDeadline(time.Time) error { return nil }

type nopPacketConn struct{}

func (npc *nopPacketConn) WriteTo(b []byte, _ net.Addr) (n int, err error) { return len(b), nil }
func (npc *nopPacketConn) ReadFrom([]byte) (int, net.Addr, error)          { return 0, nil, io.EOF }
func (npc *nopPacketConn) Close() error                                    { return nil }
func (npc *nopPacketConn) LocalAddr() net.Addr                             { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (npc *nopPacketConn) SetDeadline(time.Time) error                     { return nil }
func (npc *nopPacketConn) SetReadDeadline(time.Time) error                 { return nil }
func (npc *nopPacketConn) SetWriteDeadline(time.Time) error                { return nil }
