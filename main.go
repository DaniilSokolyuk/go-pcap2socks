package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
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
	"github.com/jackpal/gateway"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

//go:embed config.json
var configData string

func main() {
	// Setup logging - check SLOG_LEVEL env var
	logLevel := slog.LevelInfo // Default to debug
	if lvl := os.Getenv("SLOG_LEVEL"); lvl != "" {
		switch lvl {
		case "debug", "DEBUG":
			logLevel = slog.LevelDebug
		case "info", "INFO":
			logLevel = slog.LevelInfo
		case "warn", "WARN":
			logLevel = slog.LevelWarn
		case "error", "ERROR":
			logLevel = slog.LevelError
		}
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}
	handler := slog.NewTextHandler(os.Stdout, opts)
	slog.SetDefault(slog.New(handler))

	// get config file from first argument or use config.json
	var cfgFile string
	if len(os.Args) > 1 {
		cfgFile = os.Args[1]
	} else {
		executable, err := os.Executable()
		if err != nil {
			slog.Error("get executable error", slog.Any("err", err))
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
			slog.Error("write config error", slog.Any("file", cfgFile), slog.Any("err", err))
			return
		}
	}

	config, err := cfg.Load(cfgFile)
	if err != nil {
		slog.Error("load config error", slog.Any("file", cfgFile), slog.Any("err", err))
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
				slog.Error("execute command error", slog.Any("err", err))
			}

			err = cmd.Wait()
			if err != nil {

			}
		}()
	}

	err = run(config)
	if err != nil {
		slog.Error("run error", slog.Any("err", err))
		return
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Hello world!"))
	})
	log.Fatal(http.ListenAndServe(":8085", nil))
}

func run(cfg *cfg.Config) error {
	// Find the interface first
	ifce := findInterface(cfg.PCAP.InterfaceGateway)
	slog.Info("Using ethernet interface", "interface", ifce.Name, "mac", ifce.HardwareAddr.String())

	// Parse network configuration
	netConfig, err := parseNetworkConfig(cfg.PCAP, ifce)
	if err != nil {
		return err
	}

	// Display network configuration
	displayNetworkConfig(netConfig)

	proxies := make(map[string]proxy.Proxy)
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
		case outbound.DNS != nil:
			p = proxy.NewDNS(cfg.DNS, ifce.Name)
		default:
			return fmt.Errorf("invalid outbound: %+v", outbound)
		}

		proxies[outbound.Tag] = p
	}

	_defaultProxy = proxy.NewRouter(cfg.Routing.Rules, proxies)
	proxy.SetDialer(_defaultProxy)

	_defaultDevice, err = device.Open(cfg.PCAP, cfg.Capture, ifce, netConfig, func() device.Stacker {
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
		slog.Error("create stack error", slog.Any("err", err))
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

func findInterface(cfgIfce string) net.Interface {
	var targetIP net.IP
	if cfgIfce != "" {
		targetIP = net.ParseIP(cfgIfce)
		if targetIP == nil {
			panic(fmt.Errorf("parse ip error: %s", cfgIfce))
		}
	} else {
		var err error
		targetIP, err = gateway.DiscoverInterface()
		if err != nil {
			panic(fmt.Errorf("discover interface error: %w", err))
		}
	}

	// Get a list of all interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip4 := ipnet.IP.To4()
			if ip4 != nil && bytes.Equal(ip4, targetIP.To4()) {
				return iface
			}
		}
	}

	panic(fmt.Errorf("interface with IP %s not found", targetIP))
}

func parseNetworkConfig(pcapCfg cfg.PCAP, ifce net.Interface) (*device.NetworkConfig, error) {
	// Parse network CIDR
	_, network, err := net.ParseCIDR(pcapCfg.Network)
	if err != nil {
		return nil, fmt.Errorf("parse cidr error: %w", err)
	}

	// Parse local IP
	localIP := net.ParseIP(pcapCfg.LocalIP)
	if localIP == nil {
		return nil, fmt.Errorf("parse local ip error: %s", pcapCfg.LocalIP)
	}

	localIP = localIP.To4()
	if !network.Contains(localIP) {
		return nil, fmt.Errorf("local ip (%s) not in network (%s)", localIP, network)
	}

	// Parse or use interface MAC
	var localMAC net.HardwareAddr
	if pcapCfg.LocalMAC != "" {
		localMAC, err = net.ParseMAC(pcapCfg.LocalMAC)
		if err != nil {
			return nil, fmt.Errorf("parse local mac error: %w", err)
		}
	} else {
		localMAC = ifce.HardwareAddr
	}

	// Set MTU
	mtu := pcapCfg.MTU
	if mtu == 0 {
		mtu = uint32(ifce.MTU)
	}

	return &device.NetworkConfig{
		Network:  network,
		LocalIP:  localIP,
		LocalMAC: localMAC,
		MTU:      mtu,
	}, nil
}

func displayNetworkConfig(config *device.NetworkConfig) {
	// Calculate IP range
	ipRangeStart, ipRangeEnd := calculateIPRange(config.Network, config.LocalIP)
	recommendedMTU := calculateRecommendedMTU(config.MTU)

	// Log network settings in a cleaner format
	slog.Info("Configure your device with these network settings:")
	slog.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	slog.Info(fmt.Sprintf("  IP Address:     %s - %s", ipRangeStart.String(), ipRangeEnd.String()))
	slog.Info(fmt.Sprintf("  Subnet Mask:    %s", net.IP(config.Network.Mask).String()))
	slog.Info(fmt.Sprintf("  Gateway:        %s", config.LocalIP.String()))
	slog.Info(fmt.Sprintf("  MTU:            %d (or lower)", recommendedMTU))
	slog.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

// calculateIPRange calculates the usable IP range for the given network
func calculateIPRange(network *net.IPNet, gatewayIP net.IP) (start, end net.IP) {
	networkIP := network.IP.To4()
	start = make(net.IP, 4)
	end = make(net.IP, 4)

	// Get the network size
	ones, bits := network.Mask.Size()
	hostBits := uint32(bits - ones)
	numHosts := (uint32(1) << hostBits) - 2 // -2 for network and broadcast

	// Calculate start IP (network + 1)
	binary.BigEndian.PutUint32(start, binary.BigEndian.Uint32(networkIP)+1)

	// Calculate end IP (broadcast - 1)
	broadcastInt := binary.BigEndian.Uint32(networkIP) | ((1 << hostBits) - 1)
	binary.BigEndian.PutUint32(end, broadcastInt-1)

	// Exclude gateway IP from the range
	if bytes.Equal(start, gatewayIP) && numHosts > 1 {
		binary.BigEndian.PutUint32(start, binary.BigEndian.Uint32(start)+1)
	} else if bytes.Equal(end, gatewayIP) && numHosts > 1 {
		binary.BigEndian.PutUint32(end, binary.BigEndian.Uint32(end)-1)
	}

	return start, end
}

// calculateRecommendedMTU returns a recommended MTU value
func calculateRecommendedMTU(mtu uint32) uint32 {
	const ethernetHeaderSize = 14
	const ipv4HeaderSize = 20
	const tcpHeaderSize = 20
	const pppoeHeaderSize = 8

	// Account for common overhead
	recommendedMTU := mtu - ethernetHeaderSize - ipv4HeaderSize - tcpHeaderSize

	// Common values
	if recommendedMTU > 1500-pppoeHeaderSize {
		recommendedMTU = 1500 - pppoeHeaderSize // PPPoE environments
	}

	return recommendedMTU
}
