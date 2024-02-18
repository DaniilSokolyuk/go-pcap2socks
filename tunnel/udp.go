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

var UdpSessionTimeout = 60 * time.Minute

func HandleUDPConn(uc adapter.UDPConn) {
	metadata := uc.MD()

	pc, err := proxy.DialUDP(metadata)
	if err != nil {
		slog.Warn("[UDP] dial error: ", "error", err)
		return
	}

	slog.Info("[UDP] Connection", "source", metadata.SourceAddress(), "dest", metadata.DestinationAddress())

	wg := sync.WaitGroup{}
	wg.Add(2)

	go handleRemoteToLocal(pc, uc, &wg)
	go handleLocalToRemote(uc, pc, &wg)
	wg.Wait()

	uc.Close()
	slog.Info("[UDP] Connection closed", "source", metadata.SourceAddress(), "dest", metadata.DestinationAddress())
}

func handleRemoteToLocal(pc net.PacketConn, uc net.PacketConn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer pc.Close()

	buf := pool.Get(pool.MaxSegmentSize)
	defer pool.Put(buf)

	for {
		pc.SetReadDeadline(time.Now().Add(UdpSessionTimeout))
		n, dest, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, io.ErrClosedPipe) {
				slog.Warn("[UDP] pipe closed: %v", err)
				return
			}
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				slog.Warn("[UDP] read error: %v", err)
			}

			return
		}

		if _, err := uc.WriteTo(buf[:n], dest); err != nil {
			slog.Warn("[UDP] write error", "source", uc.LocalAddr(), "dest", dest, "error", err)
			return
		}
	}
}

func handleLocalToRemote(uc net.PacketConn, pc net.PacketConn, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := pool.Get(pool.MaxSegmentSize)
	defer pool.Put(buf)

	for {
		n, dest, err := uc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, io.ErrClosedPipe) {
				slog.Warn("[UDP] pipe closed: %v", err)
				return
			}
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				slog.Warn("[UDP] read error: %v", err)
			}
			return
		}

		if _, err := pc.WriteTo(buf[:n], dest); err != nil {
			slog.Warn("[UDP] write error", "source", uc.LocalAddr(), "dest", dest, "error", err)
			return
		}
	}
}
