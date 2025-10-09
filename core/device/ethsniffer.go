package device

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// pcapPacket represents a packet to be written to the PCAP file
type pcapPacket struct {
	info gopacket.CaptureInfo
	data []byte
}

// Endpoint wraps a LinkEndpoint and captures all packets to PCAP
type Endpoint struct {
	nested.Endpoint

	writer  *pcapgo.Writer
	file    *os.File
	packets chan pcapPacket
	wg      sync.WaitGroup
}

var _ stack.GSOEndpoint = (*Endpoint)(nil)
var _ stack.LinkEndpoint = (*Endpoint)(nil)
var _ stack.NetworkDispatcher = (*Endpoint)(nil)

// NewEthSniffer creates a LinkEndpoint wrapper that captures packets to PCAP
func NewEthSniffer(lower stack.LinkEndpoint, outputFile string) (*Endpoint, error) {
	// Create output filename with timestamp
	if outputFile == "" {
		outputFile = fmt.Sprintf("capture_%s.pcap", time.Now().Format("20060102_150405"))
	} else {
		// Add timestamp before extension if filename is provided
		ext := ".pcap"
		if idx := strings.LastIndex(outputFile, "."); idx != -1 {
			ext = outputFile[idx:]
			outputFile = outputFile[:idx]
		}
		outputFile = fmt.Sprintf("%s_%s%s", outputFile, time.Now().Format("20060102_150405"), ext)
	}

	// Create PCAP file
	f, err := os.Create(outputFile)
	if err != nil {
		return nil, fmt.Errorf("create PCAP file: %w", err)
	}

	// Create PCAP writer with Ethernet link type
	w := pcapgo.NewWriter(f)
	err = w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write PCAP header: %w", err)
	}

	e := &Endpoint{
		writer:  w,
		file:    f,
		packets: make(chan pcapPacket, 1000),
	}

	// Initialize nested endpoint
	e.Endpoint.Init(lower, e)

	// Start writer goroutine
	e.wg.Add(1)
	go e.packetWriter()

	slog.Info("Ethernet PCAP capture enabled", "outputFile", outputFile)

	return e, nil
}

// DeliverNetworkPacket implements stack.NetworkDispatcher - captures incoming packets
func (e *Endpoint) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.capturePacket(pkt)
	e.Endpoint.DeliverNetworkPacket(protocol, pkt)
}

// WritePackets implements stack.LinkEndpoint - captures outgoing packets
func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	for _, pkt := range pkts.AsSlice() {
		e.capturePacket(pkt)
	}
	return e.Endpoint.WritePackets(pkts)
}

// capturePacket captures a PacketBuffer to PCAP
func (e *Endpoint) capturePacket(pkt *stack.PacketBuffer) {
	// Convert PacketBuffer to bytes (full Ethernet frame)
	view := pkt.ToView()
	defer view.Release()

	data := view.AsSlice()
	if len(data) == 0 {
		return
	}

	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(data),
		Length:        len(data),
	}

	// Send packet to channel (non-blocking)
	select {
	case e.packets <- pcapPacket{info: ci, data: append([]byte(nil), data...)}:
	default:
		slog.Warn("PCAP capture channel full, dropping packet")
	}
}

// packetWriter reads packets from the channel and writes them to the PCAP file
func (e *Endpoint) packetWriter() {
	defer e.wg.Done()

	for pkt := range e.packets {
		err := e.writer.WritePacket(pkt.info, pkt.data)
		if err != nil {
			slog.Error("Failed to write packet to PCAP", "error", err)
		}
	}
}

// Close closes the PCAP capture
func (e *Endpoint) Close() {
	// Close channel and wait for writer to finish
	close(e.packets)
	e.wg.Wait()

	// Close file
	if e.file != nil {
		_ = e.file.Close()
		slog.Info("PCAP capture file closed")
	}

	// Close child endpoint
	e.Endpoint.Close()
}
