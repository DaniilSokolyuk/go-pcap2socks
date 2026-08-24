// Package e2e runs the whole engine end to end without a pcap driver.
//
// A fake console (a second gVisor stack) is wired to the engine's device
// through an in-memory ethernet segment. Everything above the frame source is
// the real thing: gVisor, the TCP forwarder, the UDP NAT, the router and the
// proxy implementations dialling real loopback sockets.
package e2e

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/device"
	"github.com/DaniilSokolyuk/go-pcap2socks/engine"
)

const (
	// DefaultNetwork is the segment the fake console lives on.
	DefaultNetwork = "172.26.0.0/16"
	// DefaultGatewayIP is the address the engine answers on.
	DefaultGatewayIP = "172.26.0.1"
	// DefaultClientIP is the fake console.
	DefaultClientIP = "172.26.0.5"

	defaultMTU = 1500
)

var (
	gatewayMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	clientMAC  = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x05}
)

// Harness is a running engine plus the fake console attached to it.
type Harness struct {
	Engine *engine.Engine
	Client *Client
	Source *device.MemSource

	Gateway netip.Addr

	cancel   context.CancelFunc
	done     chan struct{}
	stopOnce sync.Once
}

// Start brings up an engine with the given config, wires a fake console to it
// and registers cleanup with t.
//
// The engine uses process wide singletons (the tunnel queue and the default
// proxy dialer), so harnesses must not run in parallel.
func Start(t *testing.T, config *cfg.Config) *Harness {
	t.Helper()

	h := StartRaw(t, config)

	_, network, err := net.ParseCIDR(DefaultNetwork)
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	prefixLen, _ := network.Mask.Size()

	client, err := NewClient(netip.MustParseAddr(DefaultClientIP), clientMAC, h.Gateway, prefixLen, defaultMTU)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	h.Client = client

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.done = make(chan struct{})
	go h.wire(ctx)

	// t.Cleanup is LIFO, so this runs before the h.Stop that StartRaw
	// registered. The wire pump has to be stopped before the client stack goes
	// away, otherwise it can inject a frame into a closed stack.
	t.Cleanup(func() {
		h.Stop()
		client.Close()
	})

	// The gratuitous ARP the device emits on open is already on the wire; give
	// the pump a moment so tests start from a settled state.
	time.Sleep(10 * time.Millisecond)

	return h
}

// StartRaw brings up an engine attached to an in-memory segment with nothing
// else on it. Tests drive the wire themselves via h.Source, which is what link
// layer tests need: no client stack competes for the emitted frames.
func StartRaw(t *testing.T, config *cfg.Config) *Harness {
	t.Helper()

	gateway := netip.MustParseAddr(DefaultGatewayIP)

	_, network, err := net.ParseCIDR(DefaultNetwork)
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}

	netConfig := &device.NetworkConfig{
		Network:  network,
		LocalIP:  net.IP(gateway.AsSlice()),
		LocalMAC: gatewayMAC,
		MTU:      defaultMTU,
	}

	source := device.NewMemSource(512)

	eng, err := engine.Start(engine.Options{
		Config:    config,
		Interface: net.Interface{Name: "e2e0", MTU: defaultMTU, HardwareAddr: gatewayMAC},
		Network:   netConfig,
		Source:    source,
	})
	if err != nil {
		t.Fatalf("start engine: %v", err)
	}

	h := &Harness{
		Engine:  eng,
		Source:  source,
		Gateway: gateway,
	}

	t.Cleanup(h.Stop)

	return h
}

// wire moves frames between the client stack and the device's frame source.
// h.done is closed only once both directions have stopped, so Stop can hand
// back to the caller knowing nothing will touch the client stack again.
func (h *Harness) wire(ctx context.Context) {
	defer close(h.done)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		// device -> client
		defer wg.Done()
		for {
			select {
			case frame, ok := <-h.Source.Outbound():
				if !ok {
					return
				}
				h.Client.InjectFrame(frame)
			case <-ctx.Done():
				return
			case <-h.Source.Done():
				return
			}
		}
	}()

	go func() {
		// client -> device
		defer wg.Done()
		for {
			pkt := h.Client.ch.ReadContext(ctx)
			if pkt == nil {
				return
			}

			view := pkt.ToView()
			h.Source.Inject(view.AsSlice())
			view.Release()
			pkt.DecRef()
		}
	}()

	wg.Wait()
}

// Stop tears the harness down. It is idempotent.
func (h *Harness) Stop() {
	h.stopOnce.Do(func() {
		if h.cancel != nil {
			h.cancel()
		}
		_ = h.Engine.Close()
		if h.done != nil {
			<-h.done
		}
	})
}

// ClientAddr returns the console's address with the given port.
func (h *Harness) ClientAddr(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(h.Client.IP, port)
}

// startEngineExpectingError starts an engine without a client and returns the
// startup error. Used by tests that assert on configuration validation.
func startEngineExpectingError(t *testing.T, config *cfg.Config) (*engine.Engine, error) {
	t.Helper()

	_, network, err := net.ParseCIDR(DefaultNetwork)
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}

	source := device.NewMemSource(16)
	t.Cleanup(func() { _ = source.Close() })

	eng, err := engine.Start(engine.Options{
		Config:    config,
		Interface: net.Interface{Name: "e2e0", MTU: defaultMTU, HardwareAddr: gatewayMAC},
		Network: &device.NetworkConfig{
			Network:  network,
			LocalIP:  net.ParseIP(DefaultGatewayIP).To4(),
			LocalMAC: gatewayMAC,
			MTU:      defaultMTU,
		},
		Source: source,
	})
	if eng != nil {
		t.Cleanup(func() { _ = eng.Close() })
	}

	return eng, err
}
