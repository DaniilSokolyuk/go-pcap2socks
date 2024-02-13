package proxy

import (
	"context"
	"errors"
	"net"

	M "github.com/DaniilSokolyuk/go-pcap2socks/md"
)

var _ Proxy = (*Base)(nil)

type Base struct {
	addr string
	mode Mode
}

func (b *Base) Addr() string {
	return b.addr
}

func (b *Base) Mode() Mode {
	return b.mode
}

func (b *Base) DialContext(context.Context, *M.Metadata) (net.Conn, error) {
	return nil, errors.ErrUnsupported
}

func (b *Base) DialUDP(*M.Metadata) (net.PacketConn, error) {
	return nil, errors.ErrUnsupported
}
