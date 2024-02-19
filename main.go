package main

import (
	"fmt"
	"github.com/DaniilSokolyuk/go-pcap2socks/core"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/device"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/option"
	"github.com/DaniilSokolyuk/go-pcap2socks/proxy"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"log"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
)

func main() {
	err := run()
	if err != nil {
		slog.Error("run error: %w", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello pperf!"))
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func run() error {
	var err error
	_defaultProxy, err = proxy.NewSocks5("127.0.0.1:1080", "", "")
	if err != nil {
		return fmt.Errorf("new socks5 error: %w", err)

	}
	proxy.SetDialer(_defaultProxy)

	cidr := "172.24.2.1/24"

	_defaultDevice, err = device.Open("pcap", cidr, 0, func() device.Stacker {
		return _defaultStack
	})
	if err != nil {
		return err
	}

	if _defaultStack, err = core.CreateStack(&core.Config{
		LinkEndpoint:     _defaultDevice,
		TransportHandler: &core.Tunnel{},
		MulticastGroups:  []net.IP{},
		IPV4Network:      cidr,
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
