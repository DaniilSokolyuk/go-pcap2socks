package e2e

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/option"
)

// Throughput is the wrong headline number for this project: a console cares
// about how long a packet takes while something else is downloading. That is
// latency under load, the measurement Flent's RRUL and netperf's TCP_RR
// popularised, and it is what these benchmarks report.
//
// The shape is the standard one: saturate the link with bulk TCP, run a
// constant-rate probe flow alongside it, and look at the tail of the probe's
// round trip distribution rather than its mean.
const (
	// probeInterval is how often a probe leaves, independent of whether the
	// previous one came back. Waiting for each reply would collapse the rate
	// to one probe per RTT and hide exactly the queueing being measured.
	probeInterval = 20 * time.Millisecond

	// probeWindow is how long each phase runs. At a 20ms cadence that is a few
	// hundred samples, enough for a median and a p90 but not for a meaningful
	// p99, which is why the tail is reported as p90 and max.
	probeWindow = 4 * time.Second

	// loadBytes is large enough that one connection saturates the bottleneck
	// for the whole loaded window.
	loadBytes = 512 << 20

	// probePort routes the probe flow to its own outbound, so the bulk flow
	// and the probe flow can have different upstreams behind the same engine.
	probePort = 9999
)

var probeDest = netip.AddrPortFrom(netip.MustParseAddr("203.0.113.20"), probePort)

// latencyProfiles are bottlenecked links: a rate is what makes a queue form,
// and without a queue there is no latency under load to measure.
var latencyProfiles = []linkProfile{
	{"20mbit_rtt40ms", Link{Delay: 20 * time.Millisecond, Rate: 20_000_000, QueueDepth: 128, Seed: 1}},
	{"20mbit_rtt40ms_loss0.5%", Link{Delay: 20 * time.Millisecond, Rate: 20_000_000, QueueDepth: 128, Loss: 0.005, Seed: 1}},
}

// BenchmarkLatencyUnderLoad reports the console's round trip distribution while
// a bulk download saturates the same bottleneck, for each congestion control
// and loss recovery pair.
//
//	go test ./e2e -run xxx -bench LatencyUnderLoad -benchtime 1x
func BenchmarkLatencyUnderLoad(b *testing.B) {
	for _, profile := range latencyProfiles {
		for _, tune := range tunings {
			b.Run(profile.name+"/"+tune.name, func(b *testing.B) {
				benchLatency(b, profile.link, tune)
			})
		}
	}
}

func benchLatency(b *testing.B, link Link, tune tuning) {
	b.Helper()

	bulk := StartSOCKS5(b, "", "")
	bulk.Upstream = BulkTCP(b, loadBytes)

	probes := StartSOCKS5(b, "", "")
	probes.Upstream = EchoUDP(b)

	config := NewConfig().
		Socks("", bulk.Addr, "", "").
		Socks("probe-out", probes.Addr, "", "").
		Rule(cfg.Rule{DstPort: "9999", OutboundTag: "probe-out"}).
		Build(b)

	h := StartWith(b, config, HarnessOptions{
		Link: link,
		StackOptions: []option.Option{
			option.WithTCPCongestionControl(tune.congestion),
			option.WithTCPRecovery(tune.recovery),
		},
	})

	var (
		idle, loaded latencySample
		loadedMbit   float64
	)

	b.ResetTimer()
	for range b.N {
		// Unloaded first, so the loaded numbers have a baseline from the same
		// run rather than from the link's nominal delay.
		idle = probeRTT(b, h, probeWindow)

		load := startBulkLoad(b, h)
		before := load.bytes()
		loaded = probeRTT(b, h, probeWindow)
		loadedMbit = float64(load.bytes()-before) * 8 / probeWindow.Seconds() / 1e6
		load.stop()
	}
	b.StopTimer()

	// ns/op is meaningless here - every iteration is a fixed wall clock window
	// - so the distribution is the result.
	b.ReportMetric(0, "ns/op")
	// Reported next to the latency, and first among the load metrics, because
	// without it the configuration that simply sends less always looks best:
	// an idle link has excellent latency.
	b.ReportMetric(loadedMbit, "load-mbit")
	b.ReportMetric(ms(idle.percentile(50)), "idle-p50ms")
	b.ReportMetric(ms(loaded.percentile(50)), "load-p50ms")
	b.ReportMetric(ms(loaded.percentile(90)), "load-p90ms")
	b.ReportMetric(ms(loaded.max()), "load-maxms")
	b.ReportMetric(ms(loaded.jitter()), "load-jitterms")
	b.ReportMetric(loaded.lossPercent(), "probeloss%")
	b.ReportMetric(float64(h.TailDrops()), "taildrops")
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// latencySample is one probe flow's results.
type latencySample struct {
	rtts []time.Duration
	sent int

	// jit is the RFC 3550 interarrival jitter: the smoothed mean deviation of
	// transit time between consecutive probes. It is the standard way to put a
	// single number on how uneven a flow was.
	jit time.Duration
}

func (s latencySample) percentile(p int) time.Duration {
	if len(s.rtts) == 0 {
		return 0
	}
	sorted := slices.Clone(s.rtts)
	slices.Sort(sorted)

	idx := (p * (len(sorted) - 1)) / 100
	return sorted[idx]
}

func (s latencySample) max() time.Duration {
	if len(s.rtts) == 0 {
		return 0
	}
	return slices.Max(s.rtts)
}

func (s latencySample) jitter() time.Duration { return s.jit }

func (s latencySample) lossPercent() float64 {
	if s.sent == 0 {
		return 0
	}
	return 100 * float64(s.sent-len(s.rtts)) / float64(s.sent)
}

// probeRTT runs a constant-rate UDP echo flow for window and collects the round
// trip of every probe that came back.
func probeRTT(b *testing.B, h *Harness, window time.Duration) latencySample {
	b.Helper()

	conn, err := h.Client.DialUDP()
	if err != nil {
		b.Fatalf("probe dial: %v", err)
	}
	defer conn.Close()

	dst := &net.UDPAddr{IP: net.IP(probeDest.Addr().AsSlice()), Port: int(probeDest.Port())}

	var (
		mu       sync.Mutex
		sentAt   = map[uint64]time.Time{}
		sample   latencySample
		lastRTT  time.Duration
		haveLast bool
	)

	done := make(chan struct{})

	go func() {
		defer close(done)

		buf := make([]byte, 64)
		for {
			if err := conn.SetReadDeadline(time.Now().Add(window + 2*time.Second)); err != nil {
				return
			}
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 8 {
				continue
			}
			seq := binary.BigEndian.Uint64(buf[:8])

			mu.Lock()
			start, ok := sentAt[seq]
			if ok {
				delete(sentAt, seq)
				rtt := time.Since(start)
				sample.rtts = append(sample.rtts, rtt)

				// RFC 3550: J += (|D| - J)/16, with D the change in transit
				// time between consecutive probes.
				if haveLast {
					d := rtt - lastRTT
					if d < 0 {
						d = -d
					}
					sample.jit += (d - sample.jit) / 16
				}
				lastRTT, haveLast = rtt, true
			}
			mu.Unlock()
		}
	}()

	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()

	deadline := time.Now().Add(window)
	payload := make([]byte, 32)

	for seq := uint64(0); time.Now().Before(deadline); seq++ {
		binary.BigEndian.PutUint64(payload[:8], seq)

		mu.Lock()
		sentAt[seq] = time.Now()
		sample.sent++
		mu.Unlock()

		if _, err := conn.WriteTo(payload, dst); err != nil {
			b.Fatalf("probe write: %v", err)
		}
		<-ticker.C
	}

	// Let the last probes in flight come back before closing the reader.
	time.Sleep(500 * time.Millisecond)
	_ = conn.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()

	out := sample
	out.rtts = slices.Clone(sample.rtts)
	return out
}

// bulkLoad is a download saturating the bottleneck alongside the probe flow.
type bulkLoad struct {
	counter *countingSink
	stop    func()
}

// bytes is how much the load flow has delivered so far. Sampling it across the
// probe window turns the latency numbers into a trade-off that can be read:
// latency alone would reward a configuration for stalling.
func (l bulkLoad) bytes() int64 { return l.counter.n.Load() }

type countingSink struct{ n atomic.Int64 }

func (w *countingSink) Write(p []byte) (int, error) {
	w.n.Add(int64(len(p)))
	return len(p), nil
}

// startBulkLoad opens a download that runs until stop is called, saturating
// the bottleneck for the duration of the probe window.
func startBulkLoad(b *testing.B, h *Harness) bulkLoad {
	b.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	conn, err := h.Client.DialTCP(ctx, benchDest)
	if err != nil {
		cancel()
		b.Fatalf("load dial: %v", err)
	}

	if halfCloser, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = halfCloser.CloseWrite()
	}

	sink := &countingSink{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(sink, conn)
	}()

	// Give the transfer a moment to fill the bottleneck queue, so the probes
	// measure a link that is actually loaded rather than one still ramping.
	time.Sleep(750 * time.Millisecond)

	return bulkLoad{
		counter: sink,
		stop: func() {
			cancel()
			_ = conn.Close()
			<-done
		},
	}
}
