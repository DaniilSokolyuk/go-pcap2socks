// Package tunnel forwards the connections a gVisor stack accepts to an
// outbound dialer.
package tunnel

import (
	"sync"

	"github.com/DaniilSokolyuk/go-pcap2socks/core/adapter"
	"github.com/DaniilSokolyuk/go-pcap2socks/proxy"
)

var _ adapter.TransportHandler = (*Tunnel)(nil)

// Tunnel is the TCP/UDP handler a stack dispatches accepted connections to. It
// owns its dialer and its queue, so several tunnels can run in one process
// without seeing each other.
type Tunnel struct {
	dialer proxy.Dialer

	tcpQueue  chan adapter.TCPConn
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// New starts a tunnel dialling through d. Close stops it.
func New(d proxy.Dialer) *Tunnel {
	t := &Tunnel{
		dialer:   d,
		tcpQueue: make(chan adapter.TCPConn),
		done:     make(chan struct{}),
	}

	t.wg.Add(1)
	go t.process()

	return t
}

// HandleTCP queues an accepted connection. A connection arriving after Close is
// closed rather than dropped on the floor, so the peer sees a reset instead of
// a hang.
func (t *Tunnel) HandleTCP(conn adapter.TCPConn) {
	select {
	case t.tcpQueue <- conn:
	case <-t.done:
		_ = conn.Close()
	}
}

// HandleUDP relays a session. It runs on the caller's goroutine, which the UDP
// NAT already dedicates to this session.
func (t *Tunnel) HandleUDP(conn adapter.UDPConn) {
	t.handleUDPConn(conn)
}

// Close stops accepting new connections.
//
// Sessions already being relayed are not waited for: a UDP pipe lives until it
// idles out or its connection is closed, and blocking Close on that would stall
// shutdown. They keep using this tunnel's dialer, so they cannot interfere with
// whatever is started next.
func (t *Tunnel) Close() {
	t.closeOnce.Do(func() { close(t.done) })
	t.wg.Wait()
}

func (t *Tunnel) process() {
	defer t.wg.Done()

	for {
		select {
		case conn := <-t.tcpQueue:
			go t.handleTCPConn(conn)
		case <-t.done:
			return
		}
	}
}
