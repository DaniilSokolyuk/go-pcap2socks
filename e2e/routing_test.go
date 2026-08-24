package e2e

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRoutingByDestinationPort checks a rule sends matching traffic to one
// outbound and everything else to the default one.
func TestRoutingByDestinationPort(t *testing.T) {
	echo := EchoTCP(t)

	def := StartSOCKS5(t, "", "")
	def.Upstream = echo
	special := StartSOCKS5(t, "", "")
	special.Upstream = echo

	config := NewConfig().
		Socks("", def.Addr, "", "").
		Socks("special", special.Addr, "", "").
		Rule(cfg.Rule{DstPort: "8443", OutboundTag: "special"}).
		Build(t)

	h := Start(t, config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	matched := netip.MustParseAddrPort("203.0.113.10:8443")
	unmatched := netip.MustParseAddrPort("203.0.113.10:80")

	for _, dst := range []netip.AddrPort{matched, unmatched} {
		conn, err := h.Client.DialTCP(ctx, dst)
		require.NoError(t, err, "dial %s", dst)
		require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
		_, err = conn.Write([]byte("x"))
		require.NoError(t, err)
		buf := make([]byte, 1)
		_, err = io.ReadFull(conn, buf)
		require.NoError(t, err)
		conn.Close()
	}

	assert.Equal(t, []string{matched.String()}, special.Destinations(), "port 8443 goes to the special outbound")
	assert.Equal(t, []string{unmatched.String()}, def.Destinations(), "everything else takes the default")
}

// TestRoutingBySourceIP checks src based matching, and documents that criteria
// inside a rule are combined with OR: this rule matches on the source address
// regardless of the destination port.
func TestRoutingBySourceIP(t *testing.T) {
	echo := EchoTCP(t)

	def := StartSOCKS5(t, "", "")
	def.Upstream = echo
	special := StartSOCKS5(t, "", "")
	special.Upstream = echo

	config := NewConfig().
		Socks("", def.Addr, "", "").
		Socks("special", special.Addr, "", "").
		Rule(cfg.Rule{SrcIP: []string{DefaultClientIP}, DstPort: "9999", OutboundTag: "special"}).
		Build(t)

	h := Start(t, config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dst := netip.MustParseAddrPort("203.0.113.10:80")
	conn, err := h.Client.DialTCP(ctx, dst)
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	_, err = conn.Write([]byte("x"))
	require.NoError(t, err)
	buf := make([]byte, 1)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)

	assert.Equal(t, []string{dst.String()}, special.Destinations(),
		"the source address alone is enough to match: rule criteria are ORed, not ANDed")
	assert.Empty(t, def.Destinations())
}

// TestRoutingUnknownOutboundIsRejectedAtStartup checks configuration mistakes
// surface when the engine starts rather than on the first packet.
func TestRoutingUnknownOutboundIsRejectedAtStartup(t *testing.T) {
	config := NewConfig().
		Direct("").
		Rule(cfg.Rule{DstPort: "53", OutboundTag: "missing"}).
		Build(t)

	_, err := startEngineExpectingError(t, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown outbound")
}

// TestNoDefaultOutboundIsRejected checks a config without a default outbound is
// refused instead of panicking on the first connection.
func TestNoDefaultOutboundIsRejected(t *testing.T) {
	config := NewConfig().Direct("tagged").Build(t)

	_, err := startEngineExpectingError(t, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no default outbound")
}
