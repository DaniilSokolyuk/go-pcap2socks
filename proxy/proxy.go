// Package proxy provides implementations of proxy protocols.
package proxy

import (
	"context"
	"net"
	"time"

	M "github.com/DaniilSokolyuk/go-pcap2socks/md"
)

// tcpConnectTimeout bounds the TCP connect a proxy makes to its own server.
const tcpConnectTimeout = 5 * time.Second

type Dialer interface {
	DialContext(context.Context, *M.Metadata) (net.Conn, error)
	DialUDP(*M.Metadata) (net.PacketConn, error)
}

type Proxy interface {
	Dialer
	Addr() string
	Mode() Mode
}
