package e2e

import (
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dnsDst is the resolver address the console thinks it is talking to. The
// engine intercepts anything on port 53 and answers it from its own resolver.
var dnsDst = netip.MustParseAddrPort("203.0.113.53:53")

func dnsHarness(t *testing.T, answer net.IP) *Harness {
	t.Helper()

	upstream := DNSServer(t, answer)

	config := NewConfig().
		Reject("").
		DNSOut("dns-out", upstream).
		Rule(cfg.Rule{DstPort: "53", OutboundTag: "dns-out"}).
		Build(t)

	return Start(t, config)
}

// TestDNSQuery sends a real DNS query from the fake console and checks the
// answer comes back through the dns outbound.
func TestDNSQuery(t *testing.T) {
	want := net.IPv4(198, 51, 100, 7)
	h := dnsHarness(t, want)

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	packed, err := msg.Pack()
	require.NoError(t, err)

	conn, err := h.Client.DialUDP()
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	_, err = conn.WriteTo(packed, udpAddr(t, dnsDst))
	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, from, err := conn.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, dnsDst.String(), from.String(), "answer appears to come from the resolver the console asked")

	resp := new(dns.Msg)
	require.NoError(t, resp.Unpack(buf[:n]))
	require.Len(t, resp.Answer, 1)

	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, want.To4(), a.A.To4())
	assert.Equal(t, msg.Id, resp.Id, "the query id is preserved")
}

// TestDNSRepeatedQueries checks several queries on one session all resolve.
func TestDNSRepeatedQueries(t *testing.T) {
	h := dnsHarness(t, net.IPv4(198, 51, 100, 7))

	conn, err := h.Client.DialUDP()
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	buf := make([]byte, 4096)
	for i := range 5 {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		packed, err := msg.Pack()
		require.NoError(t, err)

		_, err = conn.WriteTo(packed, udpAddr(t, dnsDst))
		require.NoError(t, err)

		n, _, err := conn.ReadFrom(buf)
		require.NoError(t, err, "query %d", i)

		resp := new(dns.Msg)
		require.NoError(t, resp.Unpack(buf[:n]))
		require.Len(t, resp.Answer, 1, "query %d", i)
	}
}

// TestDNSSessionDoesNotLeakGoroutines pins the fix for the dns connection that
// used to block forever in ReadFrom: the pipe ignored read deadlines, so every
// DNS session left a goroutine (and its NAT entry) behind for good.
func TestDNSSessionDoesNotLeakGoroutines(t *testing.T) {
	h := dnsHarness(t, net.IPv4(198, 51, 100, 7))

	before := settledGoroutines()

	for range 10 {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		packed, err := msg.Pack()
		require.NoError(t, err)

		conn, err := h.Client.DialUDP()
		require.NoError(t, err)
		require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

		_, err = conn.WriteTo(packed, udpAddr(t, dnsDst))
		require.NoError(t, err)

		buf := make([]byte, 4096)
		_, _, err = conn.ReadFrom(buf)
		require.NoError(t, err)

		require.NoError(t, conn.Close())
	}

	// Sessions are torn down by the idle timeout set in TestMain; give them a
	// generous window but return as soon as they are gone.
	after := waitForGoroutines(before+2, 20*time.Second)

	assert.LessOrEqual(t, after, before+2,
		"dns sessions must not leave goroutines behind (before=%d after=%d)", before, after)
}

// settledGoroutines lets short lived goroutines from earlier work finish before
// taking a baseline.
func settledGoroutines() int {
	time.Sleep(200 * time.Millisecond)
	return runtime.NumGoroutine()
}

// waitForGoroutines polls until the count drops to max or the deadline passes.
func waitForGoroutines(max int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)

	for {
		n := runtime.NumGoroutine()
		if n <= max || time.Now().After(deadline) {
			return n
		}
		time.Sleep(100 * time.Millisecond)
	}
}
