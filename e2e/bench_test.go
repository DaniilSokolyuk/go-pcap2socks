package e2e

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/DaniilSokolyuk/go-pcap2socks/core/option"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// benchPayload is how much the console downloads per iteration.
//
// Sized for how long the matrix takes, not for realism: at 1% loss and 40ms
// RTT a transfer runs at a few hundred KB/s, so every doubling here costs
// minutes across the matrix. Comparisons are within a profile, where all four
// tunings move the same bytes, so the absolute size only sets the slow-start
// share of each number.
const benchPayload = 1 << 20 // 1MiB

// benchDest is what the console dials. The test SOCKS5 server redirects it to
// the bulk server on loopback, which the console cannot route to directly.
var benchDest = netip.MustParseAddrPort("203.0.113.10:80")

// tuning is one combination of the two stack settings under question:
// congestion control and loss recovery.
type tuning struct {
	name       string
	congestion string
	recovery   tcpip.TCPRecovery
}

// The engine ships cubic with RACK off (core/option/option.go). Tailscale
// disabled RACK for gvisor#9778 and pinned reno for gvisor#11632; both bugs
// are fixed in the gVisor this module pins, which is why cubic came back and
// why the four combinations are worth measuring rather than assuming.
var tunings = []tuning{
	{"reno+norack", "reno", tcpip.TCPRecovery(0)},
	{"reno+rack", "reno", tcpip.TCPRACKLossDetection},
	{"cubic+norack", "cubic", tcpip.TCPRecovery(0)},
	{"cubic+rack", "cubic", tcpip.TCPRACKLossDetection},
}

// linkProfile is one emulated segment. The names describe what a console
// actually sits on: a clean wire, a decent access point, one that is starting
// to struggle, and a bad one.
type linkProfile struct {
	name string
	link Link
}

// Loss stops at 1%: the emulator drops in both directions, so at 2% a
// benchPayload transfer already takes long enough that the run stops being
// something anyone will wait for. Consoles on a struggling access point sit
// in the 0.1-1% band anyway.
// Only lossy profiles discriminate. On a clean wire, and on a delayed but
// lossless one, a transfer this size never leaves slow start, so all four
// tunings return the same number and the profile measures ramp-up rather than
// congestion control. "clean" is kept as a cheap sanity check that the harness
// itself is not the bottleneck.
var linkProfiles = []linkProfile{
	{"clean", Link{}},
	{"rtt40ms_loss0.1%", Link{Delay: 20 * time.Millisecond, Loss: 0.001, Seed: 1}},
	{"rtt40ms_loss0.5%", Link{Delay: 20 * time.Millisecond, Loss: 0.005, Seed: 1}},
	{"rtt40ms_loss1%", Link{Delay: 20 * time.Millisecond, Loss: 0.01, Seed: 1}},
}

// BenchmarkTCPDownload measures console-side download throughput through the
// whole engine for each congestion control / loss recovery pair.
//
// Run one profile at a time, for example:
//
//	go test ./e2e -run xxx -bench 'TCPDownload/rtt40ms_loss0.5' -benchtime 5x
func BenchmarkTCPDownload(b *testing.B) {
	for _, profile := range linkProfiles {
		for _, tune := range tunings {
			b.Run(profile.name+"/"+tune.name, func(b *testing.B) {
				benchDownload(b, profile.link, tune)
			})
		}
	}
}

func benchDownload(b *testing.B, link Link, tune tuning) {
	b.Helper()

	socks := StartSOCKS5(b, "", "")
	socks.Upstream = BulkTCP(b, benchPayload)

	config := NewConfig().
		Socks("", socks.Addr, "", "").
		Build(b)

	h := StartWith(b, config, HarnessOptions{
		Link: link,
		StackOptions: []option.Option{
			option.WithTCPCongestionControl(tune.congestion),
			option.WithTCPRecovery(tune.recovery),
		},
	})

	before := readCounters(h)

	b.SetBytes(benchPayload)
	b.ResetTimer()

	for range b.N {
		downloadOnce(b, h)
	}

	b.StopTimer()

	after := readCounters(h)

	// Per-iteration retransmission behaviour is the whole point of comparing
	// RACK against classic recovery, so report it next to the throughput
	// rather than leaving it to be inferred from MB/s alone.
	runs := float64(b.N)
	b.ReportMetric(float64(after.retransmits-before.retransmits)/runs, "retrans/op")
	b.ReportMetric(float64(after.timeouts-before.timeouts)/runs, "rto/op")
	b.ReportMetric(float64(after.sackRecovery-before.sackRecovery)/runs, "sackrec/op")
}

// tcpCounters is the sender-side view of how recovery went. Throughput alone
// cannot tell a configuration that recovered cheaply from one that got the
// same number by retransmitting far more.
type tcpCounters struct {
	retransmits  uint64
	timeouts     uint64
	sackRecovery uint64
}

func readCounters(h *Harness) tcpCounters {
	stats := h.Engine.Stack.Stats().TCP
	return tcpCounters{
		retransmits:  stats.Retransmits.Value(),
		timeouts:     stats.Timeouts.Value(),
		sackRecovery: stats.SACKRecovery.Value(),
	}
}

func downloadOnce(b *testing.B, h *Harness) {
	b.Helper()

	// Generous but finite: a stalled connection should fail the benchmark
	// instead of hanging the run.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := h.Client.DialTCP(ctx, benchDest)
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// The console only downloads, so close its write side straight away. The
	// SOCKS5 test double relays both directions and does not close the client
	// until the client->remote copy ends, so without this FIN the transfer
	// completes but the console never sees EOF and blocks until its deadline.
	// The half-close travels console -> engine -> proxy for real, which is
	// what the tunnel's half-close support is for.
	halfCloser, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		b.Fatalf("client connection %T cannot half-close", conn)
	}
	if err := halfCloser.CloseWrite(); err != nil {
		b.Fatalf("close write: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		b.Fatalf("set deadline: %v", err)
	}

	n, err := io.Copy(io.Discard, conn)
	if err != nil {
		b.Fatalf("download: %v (after %d bytes)", err, n)
	}
	if n != benchPayload {
		b.Fatalf("short download: got %d bytes, want %d", n, benchPayload)
	}
}
