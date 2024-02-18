package tunnel

import (
	"github.com/DaniilSokolyuk/go-pcap2socks/core/adapter"
)

// Unbuffered TCP/UDP queues.
var (
	_tcpQueue = make(chan adapter.TCPConn)
)

func init() {
	go process()
}

// TCPIn return fan-in TCP queue.
func TCPIn() chan<- adapter.TCPConn {
	return _tcpQueue
}

func process() {
	for {
		select {
		case conn := <-_tcpQueue:
			go handleTCPConn(conn)
		}
	}
}
