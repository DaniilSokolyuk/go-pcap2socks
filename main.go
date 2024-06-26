package main

import (
	_ "embed"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"path"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	"github.com/DaniilSokolyuk/go-pcap2socks/core"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/device"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/option"
	"github.com/DaniilSokolyuk/go-pcap2socks/proxy"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

//go:embed config.json
var configData string

func main() {
	// get config file from first argument or use config.json
	var cfgFile string
	if len(os.Args) > 1 {
		cfgFile = os.Args[1]
	} else {
		executable, err := os.Executable()
		if err != nil {
			slog.Error("get executable error", "error", err)
			return
		}

		cfgFile = path.Join(path.Dir(executable), "config.json")
	}

	cfgExists := cfg.Exists(cfgFile)
	if !cfgExists {
		slog.Info("Config file not found, creating a new one", "file", cfgFile)
		//path to near executable file
		err := os.WriteFile(cfgFile, []byte(configData), 0666)
		if err != nil {
			slog.Error("write config error", "file", cfgFile, "error", err)
			return
		}
	}

	config, err := cfg.Load(cfgFile)
	if err != nil {
		slog.Error("load config error", "file", cfgFile, "error", err)
		return
	}
	slog.Info("Config loaded", "file", cfgFile)

	if len(config.ExecuteOnStart) > 0 {
		slog.Info("Executing commands on start", "cmd", config.ExecuteOnStart)

		var cmd *exec.Cmd
		if len(config.ExecuteOnStart) > 1 {
			cmd = exec.Command(config.ExecuteOnStart[0], config.ExecuteOnStart[1:]...)
		} else {
			cmd = exec.Command(config.ExecuteOnStart[0])
		}

		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		go func() {
			err := cmd.Start()
			if err != nil {
				slog.Error("execute command error", "error", err)
			}

			err = cmd.Wait()
			if err != nil {

			}
		}()
	}

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
