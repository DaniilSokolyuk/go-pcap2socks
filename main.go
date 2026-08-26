package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"runtime"
	"syscall"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/device"
	"github.com/DaniilSokolyuk/go-pcap2socks/engine"
	"github.com/jackpal/gateway"
)

//go:embed config.json
var configData string

func main() {
	setupLogging()

	// Check for config command
	if len(os.Args) > 1 && os.Args[1] == "config" {
		openConfigInEditor()
		return
	}

	if err := run(); err != nil {
		slog.Error("run error", slog.Any("err", err))
		os.Exit(1)
	}
}

func run() error {
	cfgFile, err := configPath()
	if err != nil {
		return err
	}

	if !cfg.Exists(cfgFile) {
		slog.Info("Config file not found, creating a new one", "file", cfgFile)
		if err = os.WriteFile(cfgFile, []byte(configData), 0o666); err != nil {
			return fmt.Errorf("write config %s: %w", cfgFile, err)
		}
	}

	config, err := cfg.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("load config %s: %w", cfgFile, err)
	}
	slog.Info("Config loaded", "file", cfgFile)

	executeOnStart(config)

	ifce, err := findInterface(config.PCAP.InterfaceGateway)
	if err != nil {
		return err
	}
	slog.Info("Using ethernet interface", "interface", ifce.Name, "mac", ifce.HardwareAddr.String())

	netConfig, err := engine.ParseNetworkConfig(config.PCAP, ifce)
	if err != nil {
		return err
	}
	displayNetworkConfig(netConfig)

	eng, err := engine.Start(engine.Options{
		Config:    config,
		Interface: ifce,
		Network:   netConfig,
	})
	if err != nil {
		return err
	}
	defer eng.Close()

	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("Hello world!"))
		})
		if err := http.ListenAndServe(":8085", nil); err != nil {
			slog.Warn("debug http server stopped", slog.Any("err", err))
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sig:
		slog.Info("Shutting down")
		return nil
	case <-eng.Done():
		// The capture died under us. Staying up would leave a process that
		// looks healthy but routes nothing.
		return fmt.Errorf("capture stopped")
	}
}

func setupLogging() {
	logLevel := slog.LevelInfo
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

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})))
}

// configPath returns the config file from the first argument, or config.json
// next to the executable.
func configPath() (string, error) {
	if len(os.Args) > 1 {
		return os.Args[1], nil
	}

	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("get executable: %w", err)
	}

	return path.Join(path.Dir(executable), "config.json"), nil
}

func executeOnStart(config *cfg.Config) {
	if len(config.ExecuteOnStart) == 0 {
		return
	}

	slog.Info("Executing commands on start", "cmd", config.ExecuteOnStart)

	cmd := exec.Command(config.ExecuteOnStart[0], config.ExecuteOnStart[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	go func() {
		if err := cmd.Run(); err != nil {
			slog.Error("execute command error", slog.Any("err", err))
		}
	}()
}

func findInterface(cfgIfce string) (net.Interface, error) {
	var targetIP net.IP
	if cfgIfce != "" {
		targetIP = net.ParseIP(cfgIfce)
		if targetIP == nil {
			return net.Interface{}, fmt.Errorf("parse interface gateway ip: %s", cfgIfce)
		}
	} else {
		var err error
		targetIP, err = gateway.DiscoverInterface()
		if err != nil {
			return net.Interface{}, fmt.Errorf("discover interface: %w", err)
		}
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, fmt.Errorf("list interfaces: %w", err)
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

			if ip4 := ipnet.IP.To4(); ip4 != nil && bytes.Equal(ip4, targetIP.To4()) {
				return iface, nil
			}
		}
	}

	return net.Interface{}, fmt.Errorf("interface with IP %s not found", targetIP)
}

func displayNetworkConfig(config *device.NetworkConfig) {
	ipRangeStart, ipRangeEnd := calculateIPRange(config.Network, config.LocalIP)
	recommendedMTU := calculateRecommendedMTU(config.MTU)

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

	// Account for common overhead
	return mtu - ethernetHeaderSize
}

func openConfigInEditor() {
	executable, err := os.Executable()
	if err != nil {
		slog.Error("get executable error", slog.Any("err", err))
		return
	}
	cfgFile := path.Join(path.Dir(executable), "config.json")

	if !cfg.Exists(cfgFile) {
		slog.Info("Config file not found, creating a new one", "file", cfgFile)
		if err := os.WriteFile(cfgFile, []byte(configData), 0o666); err != nil {
			slog.Error("write config error", slog.Any("file", cfgFile), slog.Any("err", err))
			return
		}
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("notepad", cfgFile)
	case "darwin":
		cmd = exec.Command("open", "-t", cfgFile)
	default: // linux and others
		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = os.Getenv("VISUAL")
		}
		if editor == "" {
			for _, e := range []string{"nano", "vim", "vi"} {
				if _, err := exec.LookPath(e); err == nil {
					editor = e
					break
				}
			}
		}
		if editor == "" {
			slog.Error("no editor found. Set EDITOR environment variable")
			return
		}
		cmd = exec.Command(editor, cfgFile)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	slog.Info("Opening config in editor", "file", cfgFile)
	if err = cmd.Run(); err != nil {
		slog.Error("failed to open editor", slog.Any("err", err))
	}
}
