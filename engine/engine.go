// Package engine wires a configuration into a running instance: a link layer
// device, a gVisor stack on top of it and the proxy router the stack forwards
// connections to.
package engine

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	"github.com/DaniilSokolyuk/go-pcap2socks/core"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/device"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/option"
	"github.com/DaniilSokolyuk/go-pcap2socks/proxy"
	"github.com/DaniilSokolyuk/go-pcap2socks/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Options describes one instance.
type Options struct {
	// Config is the parsed configuration. Required.
	Config *cfg.Config

	// Interface is the network interface to capture on. Only its name is used
	// when Source is set.
	Interface net.Interface

	// Network is the parsed pcap network configuration. Required.
	Network *device.NetworkConfig

	// Source, when set, replaces the live pcap handle. Tests pass a
	// device.MemSource here to run the whole engine without a pcap driver.
	Source device.FrameSource

	// StackOptions are applied after option.WithDefault, so they override it.
	// Benchmarks use this to vary one stack setting at a time; production
	// leaves it empty.
	StackOptions []option.Option
}

// Engine is a running instance. Nothing about it is process wide - the only
// remaining process wide knob is tunnel.SetUDPSessionTimeout - so several can
// run side by side.
type Engine struct {
	Stack  *stack.Stack
	NicID  tcpip.NICID
	Device device.Device
	Proxy  proxy.Proxy
	Tunnel *tunnel.Tunnel
}

// Done is closed when the device stops reading frames. Callers that want to
// exit when the capture dies - rather than keep running as a no-op router -
// should select on it.
func (e *Engine) Done() <-chan struct{} {
	return e.Device.Done()
}

// Start builds the proxies, the device and the stack, and starts forwarding.
func Start(opts Options) (*Engine, error) {
	if opts.Config == nil {
		return nil, fmt.Errorf("config is required")
	}
	if opts.Network == nil {
		return nil, fmt.Errorf("network config is required")
	}

	router, err := buildProxy(opts.Config, opts.Interface.Name)
	if err != nil {
		return nil, err
	}

	e := &Engine{
		Proxy:  router,
		Tunnel: tunnel.New(router),
	}

	if opts.Source != nil {
		e.Device, err = device.OpenWithSource(opts.Config.Capture, opts.Source, "mem", opts.Network)
	} else {
		e.Device, err = device.Open(opts.Config.Capture, opts.Interface, opts.Network)
	}
	if err != nil {
		e.Tunnel.Close()
		return nil, fmt.Errorf("open device: %w", err)
	}

	s, nicID, err := core.NewStack(&core.Config{
		TransportHandler: e.Tunnel,
		Options:          opts.StackOptions,
	})
	if err != nil {
		e.Device.Close()
		e.Tunnel.Close()
		return nil, fmt.Errorf("create stack: %w", err)
	}
	e.Stack = s
	e.NicID = nicID

	// The device has to know where to record neighbors before AttachNIC, which
	// is what starts the dispatch loop: after that, frames can arrive at any
	// moment.
	e.Device.AttachNeighborCache(s, nicID)

	if err := core.AttachNIC(s, nicID, e.Device); err != nil {
		_ = e.Close()
		return nil, fmt.Errorf("attach nic: %w", err)
	}

	return e, nil
}

// Close tears the instance down.
func (e *Engine) Close() error {
	if e.Device != nil {
		e.Device.Close()
		// Wait for the dispatch loop to finish delivering any in-flight frame
		// and exit before touching the stack. Stack.Wait waits for this
		// endpoint while holding the stack lock, and delivering a frame can
		// need that same lock - a late segment for a connection that no longer
		// exists answers with a RST via Stack.FindRoute - so closing the stack
		// with a delivery still in flight deadlocks shutdown.
		e.Device.Wait()
	}
	if e.Stack != nil {
		e.Stack.Close()
		e.Stack.Wait()
	}
	if e.Tunnel != nil {
		e.Tunnel.Close()
	}
	return nil
}

func buildProxy(config *cfg.Config, interfaceName string) (proxy.Proxy, error) {
	proxies := make(map[string]proxy.Proxy, len(config.Outbounds))

	for _, outbound := range config.Outbounds {
		var (
			p   proxy.Proxy
			err error
		)

		switch {
		case outbound.Direct != nil:
			p = proxy.NewDirect()
		case outbound.Socks != nil:
			p, err = proxy.NewSocks5(outbound.Socks.Address, outbound.Socks.Username, outbound.Socks.Password)
			if err != nil {
				return nil, fmt.Errorf("new socks5 error: %w", err)
			}
		case outbound.Reject != nil:
			p = proxy.NewReject()
		case outbound.DNS != nil:
			p = proxy.NewDNS(config.DNS, interfaceName)
		default:
			return nil, fmt.Errorf("invalid outbound: %+v", outbound)
		}

		if _, dup := proxies[outbound.Tag]; dup {
			return nil, fmt.Errorf("duplicate outbound tag %q", outbound.Tag)
		}

		proxies[outbound.Tag] = p
	}

	if _, ok := proxies[""]; !ok {
		return nil, fmt.Errorf("no default outbound: exactly one outbound must have an empty tag")
	}

	for _, rule := range config.Routing.Rules {
		if _, ok := proxies[rule.OutboundTag]; !ok {
			return nil, fmt.Errorf("routing rule references unknown outbound %q", rule.OutboundTag)
		}
	}

	slog.Debug("outbounds ready", "count", len(proxies))

	return proxy.NewRouter(config.Routing.Rules, proxies), nil
}
