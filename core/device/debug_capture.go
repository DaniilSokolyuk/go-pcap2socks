package device

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// debugPacket represents a packet to be written to the debug PCAP file
type debugPacket struct {
	info gopacket.CaptureInfo
	data []byte
}

// DebugCapture handles PCAP capture for debugging
type DebugCapture struct {
	writer   *pcapgo.Writer
	targetIP net.IP
	file     *os.File
	packets  chan debugPacket
	wg       sync.WaitGroup
}

// NewDebugCapture creates a new debug capture instance
func NewDebugCapture(targetIP, outputFile string) (*DebugCapture, error) {
	if targetIP == "" {
		return nil, fmt.Errorf("target IP is required")
	}

	ip := net.ParseIP(targetIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid target IP: %s", targetIP)
	}

	// Convert to IPv4 if needed
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

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

	// Create PCAP writer
	w := pcapgo.NewWriter(f)
	err = w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write PCAP header: %w", err)
	}

	dc := &DebugCapture{
		writer:   w,
		targetIP: ip,
		file:     f,
		packets:  make(chan debugPacket, 1000),
	}

	// Start writer goroutine
	dc.wg.Add(1)
	go dc.packetWriter()

	slog.Info("PCAP capture enabled",
		"targetIP", ip.String(),
		"outputFile", outputFile)

	return dc, nil
}

// CapturePacket captures a packet if it matches the target IP
func (dc *DebugCapture) CapturePacket(data []byte, ci gopacket.CaptureInfo) {
	if dc == nil || len(data) <= 14 {
		return
	}

	ethProtocol := header.Ethernet(data)
	if ethProtocol.Type() != header.IPv4ProtocolNumber {
		return
	}

	ipProtocol := header.IPv4(data[14:])
	srcAddr := ipProtocol.SourceAddress()
	dstAddr := ipProtocol.DestinationAddress()
	srcIP := srcAddr.AsSlice()
	dstIP := dstAddr.AsSlice()

	// Capture if source or destination matches target IP
	if bytes.Equal(srcIP, dc.targetIP) || bytes.Equal(dstIP, dc.targetIP) {
		// Send packet to debug channel (non-blocking)
		select {
		case dc.packets <- debugPacket{info: ci, data: append([]byte(nil), data...)}:
		default:
			slog.Warn("Debug channel full, dropping packet")
		}
	}
}

// CaptureOutgoingPacket captures an outgoing packet with current timestamp
func (dc *DebugCapture) CaptureOutgoingPacket(data []byte) {
	if dc == nil {
		return
	}

	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(data),
		Length:        len(data),
	}

	dc.CapturePacket(data, ci)
}

// packetWriter reads packets from the channel and writes them to the PCAP file
func (dc *DebugCapture) packetWriter() {
	defer dc.wg.Done()

	for pkt := range dc.packets {
		err := dc.writer.WritePacket(pkt.info, pkt.data)
		if err != nil {
			slog.Error("Failed to write packet to PCAP", "error", err)
		}
	}
}

// Close closes the debug capture and waits for all packets to be written
func (dc *DebugCapture) Close() {
	if dc == nil {
		return
	}

	// Close channel and wait for writer to finish
	close(dc.packets)
	dc.wg.Wait()

	// Close file
	if dc.file != nil {
		_ = dc.file.Close()
		slog.Info("PCAP capture file closed")
	}
}
