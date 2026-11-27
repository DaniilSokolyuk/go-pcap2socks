//go:build netbench

// Command pcapengine runs the production engine on libpcap, sending one frame
// per call, which is how the Linux build worked before it moved to a packet
// socket of its own. It is kept as the baseline for bench/netbench and needs
// cgo and libpcap, hence the build tag.
package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/device"
	"github.com/DaniilSokolyuk/go-pcap2socks/engine"
	"github.com/gopacket/gopacket/pcap"
)

type pcapSource struct {
	handle *pcap.Handle
}

var _ device.FrameSource = (*pcapSource)(nil)

func (p *pcapSource) ReadFrame() ([]byte, error) {
	data, _, err := p.handle.ZeroCopyReadPacketData()
	return data, err
}

func (p *pcapSource) WriteFrame(frame []byte) error { return p.handle.WritePacketData(frame) }

func (p *pcapSource) Close() error {
	p.handle.Close()
	return nil
}

func openPcap(name string) (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(name)
	if err != nil {
		return nil, err
	}
	defer inactive.CleanUp()
	for _, set := range []func() error{
		func() error { return inactive.SetPromisc(true) },
		func() error { return inactive.SetSnapLen(1600) },
		func() error { return inactive.SetTimeout(pcap.BlockForever) },
		func() error { return inactive.SetImmediateMode(true) },
		func() error { return inactive.SetBufferSize(512 * 1024) },
	} {
		if err = set(); err != nil {
			return nil, err
		}
	}
	return inactive.Activate()
}

func main() {
	if err := run(); err != nil {
		slog.Error("pcapengine", "err", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: pcapengine <config.json> <interface>")
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn})))

	config, err := cfg.Load(os.Args[1])
	if err != nil {
		return err
	}
	ifce, err := net.InterfaceByName(os.Args[2])
	if err != nil {
		return err
	}
	netConfig, err := engine.ParseNetworkConfig(config.PCAP, *ifce)
	if err != nil {
		return err
	}

	handle, err := openPcap(ifce.Name)
	if err != nil {
		return err
	}
	if err = handle.SetBPFFilter(device.BPFFilter(netConfig)); err != nil {
		return err
	}

	eng, err := engine.Start(engine.Options{
		Config:    config,
		Interface: *ifce,
		Network:   netConfig,
		Source:    &pcapSource{handle: handle},
	})
	if err != nil {
		return err
	}
	fmt.Println("ready")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
	case <-eng.Done():
	}
	// pcap_close waits for a read that only returns with the next frame, so
	// skip the orderly teardown and let the process exit.
	return nil
}
