package tunnel

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/DaniilSokolyuk/go-pcap2socks/common/pool"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/adapter"
	"github.com/DaniilSokolyuk/go-pcap2socks/proxy"
	alog "github.com/anacrolix/log"
	"github.com/anacrolix/upnp"
)

var UdpSessionTimeout = 5 * time.Minute

type UDPMapping struct {
	device       upnp.Device
	proto        upnp.Protocol
	internalPort int
	externalPort int
}

type UDPSession struct {
	conn     net.PacketConn
	mappings []*UDPMapping
	mutex    sync.Mutex
}

var excludedPorts = map[int]bool{
	53:   true, // DNS
	123:  true, // NTP
	137:  true, // NetBIOS Name Service
	138:  true, // NetBIOS Datagram Service
	161:  true, // SNMP
	162:  true, // SNMP Trap
	1900: true, // SSDP (UPnP discovery)
}

func shouldForwardPort(port int) bool {
	// Don't forward system ports (0-1023) and excluded ports
	if port <= 1023 || excludedPorts[port] {
		return false
	}
	return true
}

func (s *UDPSession) addMapping(mapping *UDPMapping) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.mappings = append(s.mappings, mapping)
}

func (s *UDPSession) cleanup() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, mapping := range s.mappings {
		err := mapping.device.DeletePortMapping(mapping.proto, mapping.externalPort)
		if err != nil {
			slog.Warn("Failed to remove UPnP port mapping",
				"device", mapping.device.GetLocalIPAddress(),
				"internalPort", mapping.internalPort,
				"externalPort", mapping.externalPort,
				"error", err)
		} else {
			slog.Info("Successfully removed UPnP port mapping",
				"device", mapping.device.GetLocalIPAddress(),
				"internalPort", mapping.internalPort,
				"externalPort", mapping.externalPort)
		}
	}
	s.mappings = nil
}

func addPortMapping(session *UDPSession, d upnp.Device, proto upnp.Protocol, internalPort int) {
	logger := slog.With(
		"device", d.GetLocalIPAddress(),
		"proto", proto,
		"internalPort", internalPort,
	)

	externalPort, err := d.AddPortMapping(proto, internalPort, internalPort, "go-pcap2socks", 0)
	if err != nil {
		logger.Warn("Failed to add UPnP port mapping", "error", err)
		return
	}

	mapping := &UDPMapping{
		device:       d,
		proto:        proto,
		internalPort: internalPort,
		externalPort: externalPort,
	}
	session.addMapping(mapping)

	logger.Info("Successfully added UPnP port mapping", "externalPort", externalPort)
}

func setupUPnP(session *UDPSession, port int) {
	if !shouldForwardPort(port) {
		slog.Debug("Skipping UPnP setup for excluded port", "port", port)
		return
	}

	devices := upnp.Discover(0, 2*time.Second, alog.NewLogger("upnp"))
	slog.Info("Discovered UPnP devices", "count", len(devices))

	for _, d := range devices {
		go addPortMapping(session, d, upnp.UDP, port)
	}
}

func HandleUDPConn(uc adapter.UDPConn) {
	metadata := uc.MD()

	session := &UDPSession{}

	// Setup UPnP port mapping for the source port
	_, srcPort := parseAddr(metadata.Addr())
	setupUPnP(session, int(srcPort))

	pc, err := proxy.DialUDP(metadata)
	if err != nil {
		slog.Warn("[UDP] dial error: ", "error", err)
		session.cleanup()
		return
	}
	defer func() {
		pc.Close()
		session.cleanup()
	}()

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
