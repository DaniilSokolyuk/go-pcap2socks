package proxy

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	M "github.com/DaniilSokolyuk/go-pcap2socks/md"
)

const tcpConnectTimeout = 5 * time.Second

var (
	_defaultDialer Dialer = &Base{}
	mu             sync.RWMutex
)

type Dialer interface {
	DialContext(context.Context, *M.Metadata) (net.Conn, error)
	DialUDP(*M.Metadata) (net.PacketConn, error)
}

type Proxy interface {
	Dialer
	Addr() string
	Mode() Mode
}

// SetDialer потокобезопасно заменяет текущий dialer.
func SetDialer(d Dialer) {
	mu.Lock()
	defer mu.Unlock()
	if old, ok := _defaultDialer.(io.Closer); ok {
		_ = old.Close()
	}
	_defaultDialer = d
}

// getDialer возвращает текущий dialer (read lock).
func getDialer() Dialer {
	mu.RLock()
	defer mu.RUnlock()
	return _defaultDialer
}

func Dial(metadata *M.Metadata) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), tcpConnectTimeout)
	defer cancel()
	return getDialer().DialContext(ctx, metadata)
}

func DialContext(ctx context.Context, metadata *M.Metadata) (net.Conn, error) {
	return getDialer().DialContext(ctx, metadata)
}

func DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	return getDialer().DialUDP(metadata)
}
