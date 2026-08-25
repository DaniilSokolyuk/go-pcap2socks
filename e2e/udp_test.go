package e2e

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/DaniilSokolyuk/go-pcap2socks/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	fakeUDPDst  = netip.MustParseAddrPort("203.0.113.20:9000")
	fakeUDPDst2 = netip.MustParseAddrPort("203.0.113.21:9001")
)

func udpAddr(t *testing.T, ap netip.AddrPort) *net.UDPAddr {
	t.Helper()
	return &net.UDPAddr{IP: net.IP(ap.Addr().AsSlice()), Port: int(ap.Port())}
}

// udpHarness starts a UDP echo server behind a SOCKS5 relay and an engine that
// routes everything to it.
func udpHarness(t *testing.T) (*Harness, *SOCKS5Server) {
	t.Helper()

	echo := EchoUDP(t)
	socks := StartSOCKS5(t, "", "")
	socks.Upstream = echo

	h := Start(t, NewConfig().Socks("", socks.Addr, "", "").Build(t))

	return h, socks
}

// TestUDPRoundTrip sends a datagram from the fake console and reads the echo
// back, exercising the UDP NAT and the SOCKS5 UDP ASSOCIATE path.
func TestUDPRoundTrip(t *testing.T) {
	h, socks := udpHarness(t)

	conn, err := h.Client.DialUDP()
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	want := []byte("ping")
	_, err = conn.WriteTo(want, udpAddr(t, fakeUDPDst))
	require.NoError(t, err)

	buf := make([]byte, 1500)
	n, from, err := conn.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, want, buf[:n])
	assert.Equal(t, fakeUDPDst.String(), from.String(), "reply appears to come from the destination")

	assert.Equal(t, []string{fakeUDPDst.String()}, socks.Destinations())
}

// TestUDPSessionIsSharedAcrossDestinations pins the NAT keying: udpnat2 keys
// sessions on the source address only, so one client port talking to two
// destinations must reuse a single session and keep both replies straight.
func TestUDPSessionIsSharedAcrossDestinations(t *testing.T) {
	h, socks := udpHarness(t)

	conn, err := h.Client.DialUDP()
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	_, err = conn.WriteTo([]byte("first"), udpAddr(t, fakeUDPDst))
	require.NoError(t, err)

	buf := make([]byte, 1500)
	n, from, err := conn.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "first", string(buf[:n]))
	assert.Equal(t, fakeUDPDst.String(), from.String())

	_, err = conn.WriteTo([]byte("second"), udpAddr(t, fakeUDPDst2))
	require.NoError(t, err)

	n, from, err = conn.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "second", string(buf[:n]))
	assert.Equal(t, fakeUDPDst2.String(), from.String(), "second destination is tracked per packet")

	assert.Equal(t, []string{fakeUDPDst.String(), fakeUDPDst2.String()}, socks.Destinations())
}

// TestUDPMultipleDatagrams checks the session survives a burst.
func TestUDPMultipleDatagrams(t *testing.T) {
	h, _ := udpHarness(t)

	conn, err := h.Client.DialUDP()
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	const count = 20
	dst := udpAddr(t, fakeUDPDst)
	buf := make([]byte, 1500)

	for i := range count {
		payload := []byte{byte(i)}
		_, err = conn.WriteTo(payload, dst)
		require.NoError(t, err)

		n, _, err := conn.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, payload, buf[:n], "datagram %d", i)
	}
}

// TestUDPSessionTimeout checks an idle session is torn down and a later
// datagram from the same port opens a fresh one.
func TestUDPSessionTimeout(t *testing.T) {
	old := tunnel.UDPSessionTimeout()
	tunnel.SetUDPSessionTimeout(300 * time.Millisecond)
	t.Cleanup(func() { tunnel.SetUDPSessionTimeout(old) })

	h, socks := udpHarness(t)

	conn, err := h.Client.DialUDP()
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	dst := udpAddr(t, fakeUDPDst)
	buf := make([]byte, 1500)

	_, err = conn.WriteTo([]byte("before"), dst)
	require.NoError(t, err)
	n, _, err := conn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "before", string(buf[:n]))

	// Let the session go idle and be reaped.
	time.Sleep(600 * time.Millisecond)

	_, err = conn.WriteTo([]byte("after"), dst)
	require.NoError(t, err)
	n, _, err = conn.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "after", string(buf[:n]))

	// A new session means the proxy saw the destination announced twice.
	assert.Len(t, socks.Destinations(), 2)
}

// TestUDPReject checks the reject outbound swallows datagrams.
func TestUDPReject(t *testing.T) {
	h := Start(t, NewConfig().Reject("").Build(t))

	conn, err := h.Client.DialUDP()
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.SetDeadline(time.Now().Add(500*time.Millisecond)))

	_, err = conn.WriteTo([]byte("dropped"), udpAddr(t, fakeUDPDst))
	require.NoError(t, err)

	buf := make([]byte, 1500)
	_, _, err = conn.ReadFrom(buf)
	require.Error(t, err, "reject must not answer")
}

// TestUDPRecoversAfterProxyDialFailure pins the fix for a dial failure leaving
// the source port blackholed: HandleUDPConn used to return without closing the
// connection, so the NAT entry stayed healthy and every later packet from the
// same port just refreshed its lifetime instead of retrying the proxy.
func TestUDPRecoversAfterProxyDialFailure(t *testing.T) {
	echo := EchoUDP(t)

	// The proxy is reachable but turns the engine away, so the dial fails at
	// the SOCKS5 handshake.
	//
	// Pointing the engine at an address nothing listens on would model a dead
	// proxy more literally, but nothing observable then says the dial was even
	// attempted, and the test has to guess how long to wait for it. That guess
	// is a coin flip: the console-to-engine path costs about a millisecond
	// normally and anywhere from 300ms to a second under the race detector. A
	// server that answers can be counted instead, which is what Accepted is
	// for, and the dial fails just as thoroughly either way.
	socks := StartSOCKS5(t, "user", "pass")
	socks.Upstream = echo

	// No credentials on this side: every dial is refused until SetAuth below.
	h := Start(t, NewConfig().Socks("", socks.Addr, "", "").Build(t))

	conn, err := h.Client.DialUDP()
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.WriteTo([]byte("lost"), udpAddr(t, fakeUDPDst))
	require.NoError(t, err)

	// The recovery only means anything once a dial has actually failed, so wait
	// for the engine to have reached the proxy rather than assuming it did.
	waitForAccepted(t, socks, 1)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
	buf := make([]byte, 1500)
	_, _, err = conn.ReadFrom(buf)
	require.Error(t, err, "the proxy refused the engine, so nothing can answer")

	socks.SetAuth("", "")

	// Same socket, same source port: the session must be retried, not served
	// from the stale NAT entry.
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	want := []byte("ping")
	_, err = conn.WriteTo(want, udpAddr(t, fakeUDPDst))
	require.NoError(t, err)

	n, _, err := conn.ReadFrom(buf)
	require.NoError(t, err, "the source port must recover once the proxy accepts")
	assert.Equal(t, want, buf[:n])
}

// waitForAccepted blocks until the proxy has accepted at least n connections.
func waitForAccepted(t *testing.T, socks *SOCKS5Server, n int) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for socks.Accepted() < n {
		if time.Now().After(deadline) {
			t.Fatalf("proxy accepted %d connections, want %d", socks.Accepted(), n)
		}
		time.Sleep(time.Millisecond)
	}
}
