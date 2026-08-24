# Testing

Everything runs with plain `go test`: no root, no pcap driver, no network access
beyond loopback. The whole suite takes a few seconds.

```bash
make test        # everything
make test-race   # everything, with the race detector (what CI runs)
make test-e2e    # end-to-end tests only, verbose
make cover       # total statement coverage
```

## The idea

The only thing the tests fake is the source of ethernet frames. Everything above
it - gVisor, the TCP forwarder, the UDP NAT, the router, the SOCKS5 client, the
DNS resolver, the real loopback sockets the proxies dial - is the production
code path.

That is possible because the device is built on a narrow seam:

```go
// core/device/source.go
type FrameSource interface {
	ReadFrame() ([]byte, error)
	WriteFrame(p []byte) error
	Close() error
}
```

`pcapSource` is the production implementation. `MemSource` is a pair of channels.
`device.OpenWithSource` takes either one, so `engine.Start` can be handed a
`MemSource` and the entire application comes up in-process.

## The end-to-end harness

`e2e.Start` brings up two gVisor stacks joined by an in-memory ethernet segment:

```
┌── fake console ────────────┐        ┌── engine under test ───────┐
│ gVisor, 172.26.0.5/16      │        │ MemSource + real device    │
│ default route via gateway  │◄─wire─►│ gVisor, tunnel, router     │
│ gonet.DialTCP / DialUDP    │        │ proxies dialling loopback  │
└────────────────────────────┘        └────────────────────────────┘
                                                   │
                                    ┌──────────────┴───────────────┐
                                    │ test SOCKS5 / DNS / echo     │
                                    │ servers on 127.0.0.1         │
                                    └──────────────────────────────┘
```

A test "app" on the console is ordinary Go code:

```go
h := Start(t, NewConfig().Socks("", socks.Addr, "", "").Build(t))

conn, err := h.Client.DialTCP(ctx, netip.MustParseAddrPort("203.0.113.10:80"))
```

`e2e.StartRaw` is the same thing without the console: no client stack competes
for the frames, so link layer tests can inject and inspect frames by hand
through `h.Source`.

### Why destinations look like 203.0.113.x

gVisor refuses to route loopback destinations out of a non-loopback NIC, so the
fake console cannot dial `127.0.0.1` directly. Tests therefore target
documentation addresses (RFC 5737) and the test SOCKS5 server - a test double
anyway - redirects them to the real echo server via its `Upstream` field. The
address the console asked for is still recorded, so tests assert that the
destination survives the whole path intact.

`Direct` cannot be exercised this way, so it is covered at the component level in
`proxy/outbound_test.go` where dialling `127.0.0.1` is trivial.

## Layers

| Layer | Where | What it covers |
|---|---|---|
| Unit | `cfg`, `arpr`, `tunnel`, `transport`, `engine`, `core/device` | config parsing, ARP frame bytes, address helpers, SOCKS5 wire format (with a fuzz target), frame filtering and MAC learning |
| Component | `proxy/outbound_test.go`, `proxy/router_test.go` | each outbound against real loopback servers; rule matching |
| End to end | `e2e/` | TCP, UDP, DNS, ARP and routing through the whole engine |

## Regressions the suite pins

- `e2e.TestDNSSessionDoesNotLeakGoroutines` - DNS sessions used to strand a
  goroutine each, because the connection ignored read deadlines and blocked on
  an unbuffered channel forever. Verified to fail (20 leaked goroutines over 10
  queries) against the old implementation.
- `arpr.TestGratuitousArpEthertype` - the announcement carried the IPv4
  ethertype with an ARP body, so receivers ignored it.
- `arpr.TestSendGratuitousArpIPv6MappedAddress` - a 16 byte IPv4 address
  produced a frame with `ProtAddressSize: 16`.
- `device.TestDeviceReadReportsClosedSource` - a closed source used to make the
  dispatch loop spin at 100% CPU instead of exiting.
- `e2e.TestUDPRecoversAfterProxyDialFailure` - a failed proxy dial left the NAT
  entry healthy and unread, so the client's source port stayed blackholed for as
  long as it kept sending. Verified to fail (i/o timeout) without the fix.
- `device.TestDeviceDropsRuntFrames` and
  `device.TestDeviceDropsARPWithNonIPv4Addresses` - two panics reachable from
  the wire: an ethertype read before any length check, and an ARP body
  declaring a 16 byte protocol address reaching the neighbor cache. Both
  verified to panic without the guards.
- `device.TestDeviceLearnsNothingBeforeTheStackExists` - the device could call
  into the stack during the window between the NIC being attached and the
  engine publishing it.
- `e2e.TestEngineDoneWhenSourceDies` - the dispatch loop swallowed the read
  error, leaving a process that looked healthy but routed nothing.
- `e2e.TestUDPSessionIsSharedAcrossDestinations` - the UDP NAT keys sessions on
  the source address only; this pins the behaviour across sing upgrades.
- `proxy.TestRouterSelectsOutbound/criteria_are_ORed,_not_ANDed` - documents
  that criteria inside one routing rule match with OR, not AND.

## Constraints to keep in mind

- The tunnel queue (`tunnel._tcpQueue`) and the default proxy dialer
  (`proxy._defaultDialer`) are process wide, so e2e tests must not call
  `t.Parallel`.
- `e2e.TestMain` shortens the UDP idle timeout to 2s so sessions left behind by
  a test do not keep goroutines alive for minutes. Use
  `tunnel.SetUDPSessionTimeout` rather than assigning a package variable: it is
  read by every live pipe goroutine and is atomic for that reason.
- Test servers must close what they open in `t.Cleanup`. A SOCKS5 UDP
  association lives as long as its control connection, so waiting for it to
  time out instead would stall the suite.
