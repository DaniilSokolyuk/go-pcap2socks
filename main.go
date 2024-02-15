package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/DaniilSokolyuk/go-pcap2socks/core"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/device"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/option"
	"github.com/DaniilSokolyuk/go-pcap2socks/proxy"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func main() {
	err := run()
	if err != nil {
		slog.Error("run error: %w", err)
	}

	quitChannel := make(chan os.Signal)
	signal.Notify(quitChannel, syscall.SIGINT, syscall.SIGTERM)
	<-quitChannel
}

func run() error {
	var err error
	_defaultProxy, err = proxy.NewSocks5("127.0.0.1:1080", "", "")
	if err != nil {
		return fmt.Errorf("new socks5 error: %w", err)

	}
	proxy.SetDialer(_defaultProxy)

	_defaultDevice, err = device.Open("pcap", func() device.Stacker {
		return _defaultStack
	})
	if err != nil {
		return err
	}

	if _defaultStack, err = core.CreateStack(&core.Config{
		LinkEndpoint:     _defaultDevice,
		TransportHandler: &core.Tunnel{},
		MulticastGroups:  []net.IP{},
		Options:          []option.Option{},
	}); err != nil {
		slog.Error("create stack error: %w", err)
	}

	return nil
}

var (
	// _defaultProxy holds the default proxy for the engine.
	_defaultProxy proxy.Proxy

	// _defaultDevice holds the default device for the engine.
	_defaultDevice device.Device

	// _defaultStack holds the default stack for the engine.
	_defaultStack *stack.Stack
)
