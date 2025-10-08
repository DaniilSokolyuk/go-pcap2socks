package option

import (
	"fmt"

	"golang.org/x/time/rate"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	// defaultTimeToLive specifies the default TTL used by stack.
	defaultTimeToLive uint8 = 64

	// ipForwardingEnabled is the value used by stack to enable packet
	// forwarding between NICs.
	ipForwardingEnabled = true

	// icmpBurst is the default number of ICMP messages that can be sent in
	// a single burst.
	icmpBurst = 50

	// icmpLimit is the default maximum number of ICMP messages permitted
	// by this rate limiter.
	icmpLimit rate.Limit = 1000

	// tcpCongestionControl is the congestion control algorithm used by
	// stack. CUBIC is much faster than Reno for high-bandwidth networks.
	tcpCongestionControlAlgorithm = "reno" // "reno" or "cubic"

	// tcpDelayEnabled is the value used by stack to enable or disable
	// tcp delay option. Disable Nagle's algorithm here by default.
	tcpDelayEnabled = false

	// tcpModerateReceiveBufferEnabled is the value used by stack to
	// enable or disable tcp receive buffer auto-tuning option.
	tcpModerateReceiveBufferEnabled = true

	// tcpSACKEnabled is the value used by stack to enable or disable
	// tcp selective ACK.
	tcpSACKEnabled = true

	// tcpRecovery is the loss detection algorithm used by TCP.
	tcpRecovery = tcpip.TCPRACKLossDetection

	// TCP Receive (RX) buffer sizes - for incoming data
	// Min is unused by gVisor at the time of writing, but partially plumbed
	// for application by the TCP_WINDOW_CLAMP socket option.
	tcpRXBufMinSize = tcp.MinBufferSize
	// Default is used by gVisor at socket creation.
	tcpRXBufDefSize = tcp.DefaultReceiveBufferSize
	// Max is used by gVisor to cap the advertised receive window post-read
	// when tcp_moderate_rcvbuf=true (the default).
	tcpRXBufMaxSize = 8 << 20 // 8MiB

	// TCP Transmit (TX) buffer sizes - for outgoing data
	// Min is unused by gVisor at the time of writing.
	tcpTXBufMinSize = tcp.MinBufferSize
	// Default is used by gVisor at socket creation.
	tcpTXBufDefSize = tcp.DefaultSendBufferSize
	// Max is used by gVisor to cap the send window.
	tcpTXBufMaxSize = 6 << 20 // 6MiB
)

type Option func(*stack.Stack) error

// WithDefault sets all default values for stack.
func WithDefault() Option {
	return func(s *stack.Stack) error {
		opts := []Option{
			WithDefaultTTL(defaultTimeToLive),
			WithForwarding(ipForwardingEnabled),

			// Config default stack ICMP settings.
			WithICMPBurst(icmpBurst), WithICMPLimit(icmpLimit),

			// We expect no packet loss, therefore we can bump buffers.
			// Too large buffers thrash cache, so there is little point
			// in too large buffers.
			//
			// Ref: https://github.com/cloudflare/slirpnetstack/blob/master/stack.go
			WithTCPSendBufferSizeRange(tcpTXBufMinSize, tcpTXBufDefSize, tcpTXBufMaxSize),
			WithTCPReceiveBufferSizeRange(tcpRXBufMinSize, tcpRXBufDefSize, tcpRXBufMaxSize),

			WithTCPCongestionControl(tcpCongestionControlAlgorithm),
			WithTCPDelay(tcpDelayEnabled),

			// Receive Buffer Auto-Tuning Option, see:
			// https://github.com/google/gvisor/issues/1666
			WithTCPModerateReceiveBuffer(tcpModerateReceiveBufferEnabled),

			// TCP selective ACK Option, see:
			// https://tools.ietf.org/html/rfc2018
			WithTCPSACKEnabled(tcpSACKEnabled),

			// TCPRACKLossDetection: indicates RACK is used for loss detection and
			// recovery.
			//
			// TCPRACKStaticReoWnd: indicates the reordering window should not be
			// adjusted when DSACK is received.
			//
			// TCPRACKNoDupTh: indicates RACK should not consider the classic three
			// duplicate acknowledgements rule to mark the segments as lost. This
			// is used when reordering is not detected.
			WithTCPRecovery(tcpRecovery),
		}

		for _, opt := range opts {
			if err := opt(s); err != nil {
				return err
			}
		}

		return nil
	}
}

// WithDefaultTTL sets the default TTL used by stack.
func WithDefaultTTL(ttl uint8) Option {
	return func(s *stack.Stack) error {
		opt := tcpip.DefaultTTLOption(ttl)
		if err := s.SetNetworkProtocolOption(ipv4.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set ipv4 default TTL: %s", err)
		}
		if err := s.SetNetworkProtocolOption(ipv6.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set ipv6 default TTL: %s", err)
		}
		return nil
	}
}

// WithForwarding sets packet forwarding between NICs for IPv4 & IPv6.
func WithForwarding(v bool) Option {
	return func(s *stack.Stack) error {
		if err := s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, v); err != nil {
			return fmt.Errorf("set ipv4 forwarding: %s", err)
		}
		if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, v); err != nil {
			return fmt.Errorf("set ipv6 forwarding: %s", err)
		}
		return nil
	}
}

// WithICMPBurst sets the number of ICMP messages that can be sent
// in a single burst.
func WithICMPBurst(burst int) Option {
	return func(s *stack.Stack) error {
		s.SetICMPBurst(burst)
		return nil
	}
}

// WithICMPLimit sets the maximum number of ICMP messages permitted
// by rate limiter.
func WithICMPLimit(limit rate.Limit) Option {
	return func(s *stack.Stack) error {
		s.SetICMPLimit(limit)
		return nil
	}
}

// WithTCPSendBufferSizeRange sets the send buffer size range for TCP.
// Inspired by Tailscale's implementation.
func WithTCPSendBufferSizeRange(min, def, max int) Option {
	return func(s *stack.Stack) error {
		opt := tcpip.TCPSendBufferSizeRangeOption{
			// Min is unused by gVisor at the time of writing.
			Min: min,
			// Default is used by gVisor at socket creation.
			Default: def,
			// Max is used by gVisor to cap the send window.
			Max: max,
		}
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set TCP send buffer size range: %s", err)
		}
		return nil
	}
}

// WithTCPReceiveBufferSizeRange sets the receive buffer size range for TCP.
// Inspired by Tailscale's implementation.
func WithTCPReceiveBufferSizeRange(min, def, max int) Option {
	return func(s *stack.Stack) error {
		opt := tcpip.TCPReceiveBufferSizeRangeOption{
			// Min is unused by gVisor at the time of writing, but partially plumbed
			// for application by the TCP_WINDOW_CLAMP socket option.
			Min: min,
			// Default is used by gVisor at socket creation.
			Default: def,
			// Max is used by gVisor to cap the advertised receive window post-read
			// when tcp_moderate_rcvbuf=true (the default).
			Max: max,
		}
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set TCP receive buffer size range: %s", err)
		}
		return nil
	}
}

// WithTCPCongestionControl sets the current congestion control algorithm.
func WithTCPCongestionControl(cc string) Option {
	return func(s *stack.Stack) error {
		opt := tcpip.CongestionControlOption(cc)
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set TCP congestion control algorithm: %s", err)
		}
		return nil
	}
}

// WithTCPDelay enables or disables Nagle's algorithm in TCP.
func WithTCPDelay(v bool) Option {
	return func(s *stack.Stack) error {
		opt := tcpip.TCPDelayEnabled(v)
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set TCP delay: %s", err)
		}
		return nil
	}
}

// WithTCPModerateReceiveBuffer sets receive buffer moderation for TCP.
func WithTCPModerateReceiveBuffer(v bool) Option {
	return func(s *stack.Stack) error {
		opt := tcpip.TCPModerateReceiveBufferOption(v)
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set TCP moderate receive buffer: %s", err)
		}
		return nil
	}
}

// WithTCPSACKEnabled sets the SACK option for TCP.
func WithTCPSACKEnabled(v bool) Option {
	return func(s *stack.Stack) error {
		opt := tcpip.TCPSACKEnabled(v)
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set TCP SACK: %s", err)
		}
		return nil
	}
}

// WithTCPRecovery sets the recovery option for TCP.
func WithTCPRecovery(v tcpip.TCPRecovery) Option {
	return func(s *stack.Stack) error {
		v = tcpip.TCPRecovery(0)

		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &v); err != nil {
			return fmt.Errorf("set TCP Recovery: %s", err)
		}
		return nil
	}
}
