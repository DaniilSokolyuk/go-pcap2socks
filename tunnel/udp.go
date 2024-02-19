package tunnel

import (
	"errors"
	"github.com/DaniilSokolyuk/go-pcap2socks/common/pool"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/adapter"
	"github.com/DaniilSokolyuk/go-pcap2socks/proxy"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

var UdpSessionTimeout = 5 * time.Minute

func HandleUDPConn(uc adapter.UDPConn) {
	metadata := uc.MD()

	pc, err := proxy.DialUDP(metadata)
	if err != nil {
		slog.Warn("[UDP] dial error: ", "error", err)
		return
	}
	defer pc.Close()

	slog.Info("[UDP] Connection", "source", metadata.SourceAddress(), "dest", metadata.DestinationAddress())

	wg := sync.WaitGroup{}
	wg.Add(2)

	go pipeChannel(pc, uc, &wg)
	go pipeChannel(uc, pc, &wg)
	wg.Wait()

	uc.Close()
	slog.Info("[UDP] Connection closed", "source", metadata.SourceAddress(), "dest", metadata.DestinationAddress())
}

func pipeChannel(from net.PacketConn, to net.PacketConn, wg *sync.WaitGroup) {
	defer wg.Done()

	buf := pool.Get(pool.MaxSegmentSize)
	defer pool.Put(buf)

	for {
		from.SetReadDeadline(time.Now().Add(UdpSessionTimeout))
		n, dest, err := from.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, io.ErrClosedPipe) {
				slog.Warn("[UDP] pipe closed", "source", from.LocalAddr(), "dest", to.LocalAddr(), "error", err)
				return
			}
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				slog.Warn("[UDP] read error", "source", from.LocalAddr(), "dest", to.LocalAddr(), "error", err)
			}

			return
		}

		to.SetWriteDeadline(time.Now().Add(UdpSessionTimeout))
		if _, err := to.WriteTo(buf[:n], dest); err != nil {
			slog.Warn("[UDP] write error", "source", from.LocalAddr(), "dest", dest, "error", err)
			return
		}
	}
}
