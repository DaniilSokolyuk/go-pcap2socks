package main

import (
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"

	//_ "net/http/pprof"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	"github.com/DaniilSokolyuk/go-pcap2socks/core"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/device"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/option"
	"github.com/DaniilSokolyuk/go-pcap2socks/proxy"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func main() {
	// get config file from first argument or use config.json
	var cfgFile string
	if len(os.Args) > 1 {
		cfgFile = os.Args[1]
	} else {
		cfgFile = "config.json"
	}

	config, err := cfg.Load(cfgFile)
	if err != nil {
		slog.Error("load config error", "file", cfgFile, "error", err)
		return
	}
	slog.Info("Config loaded", "file", cfgFile)

	err = run(config)
	if err != nil {
		slog.Error("run error", "error", err)
		return
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello world!"))
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func run(cfg *cfg.Config) error {
	proxies := make(map[string]proxy.Proxy)
	var err error
	for _, outbound := range cfg.Outbounds {
		var p proxy.Proxy
		switch {
		case outbound.Direct != nil:
			p = proxy.NewDirect()
		case outbound.Socks != nil:
			p, err = proxy.NewSocks5(outbound.Socks.Address, outbound.Socks.Username, outbound.Socks.Password)
			if err != nil {
				return fmt.Errorf("new socks5 error: %w", err)
			}
		case outbound.Reject != nil:
			p = proxy.NewReject()
		default:
			return fmt.Errorf("invalid outbound: %+v", outbound)
		}

		proxies[outbound.Tag] = p
	}

	_defaultProxy = proxy.NewRouter(cfg.Routing.Rules, proxies)
	proxy.SetDialer(_defaultProxy)

	_defaultDevice, err = device.Open(cfg.PCAP, func() device.Stacker {
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
