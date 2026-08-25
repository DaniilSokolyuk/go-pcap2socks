package e2e

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

// EchoTCP starts a TCP server on loopback that echoes everything back.
func EchoTCP(t testing.TB) netip.AddrPort {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo tcp: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	return mustAddrPort(t, ln.Addr())
}

// EchoUDP starts a UDP server on loopback that echoes every datagram back to
// its sender, prefixed with nothing: the payload is returned verbatim.
func EchoUDP(t testing.TB) netip.AddrPort {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err = pc.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()

	return mustAddrPort(t, pc.LocalAddr())
}

// DNSServer starts a DNS server on loopback answering every A query with the
// given address.
func DNSServer(t testing.TB, answer net.IP) netip.AddrPort {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dns: %v", err)
	}

	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			for _, q := range req.Question {
				if q.Qtype != dns.TypeA {
					continue
				}
				rr, err := dns.NewRR(q.Name + " 60 IN A " + answer.String())
				if err != nil {
					continue
				}
				resp.Answer = append(resp.Answer, rr)
			}
			_ = w.WriteMsg(resp)
		}),
	}

	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }

	go func() { _ = srv.ActivateAndServe() }()
	<-started

	t.Cleanup(func() { _ = srv.Shutdown() })

	return mustAddrPort(t, pc.LocalAddr())
}

// SOCKS5Server is a minimal SOCKS5 server used as the outbound of the engine
// under test. It supports CONNECT and UDP ASSOCIATE, with optional
// username/password authentication.
type SOCKS5Server struct {
	Addr netip.AddrPort

	// Requested records every destination the engine asked for, in order.
	Requested []string

	// Upstream, when set, replaces every requested destination when actually
	// dialling. Tests need this because the fake console cannot route to
	// loopback, so it targets a documentation address and the proxy - which is
	// a test double anyway - sends the traffic to the real echo server.
	Upstream netip.AddrPort

	ln      net.Listener
	mu      sync.Mutex
	wg      sync.WaitGroup
	closers []io.Closer
	user    string
	pass    string

	// accepted counts connections the server has taken. It is the only signal
	// a test has that the engine actually reached the proxy, as opposed to
	// still being on its way there.
	accepted atomic.Int64
}

// Accepted returns how many connections the server has accepted so far.
func (s *SOCKS5Server) Accepted() int {
	return int(s.accepted.Load())
}

// SetAuth changes the credentials the server demands; an empty user disables
// authentication. Tests use it to turn a failing dial into a succeeding one
// without rebinding the listener.
func (s *SOCKS5Server) SetAuth(user, pass string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.user, s.pass = user, pass
}

func (s *SOCKS5Server) auth() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.user, s.pass
}

// StartSOCKS5 starts the server on loopback. Empty user disables auth.
func StartSOCKS5(t testing.TB, user, pass string) *SOCKS5Server {
	t.Helper()

	return StartSOCKS5At(t, "127.0.0.1:0", user, pass)
}

// StartSOCKS5At starts the server on a specific address. Tests that need the
// proxy to be unreachable first and reachable later use it to come back up on
// the address the engine was configured with.
func StartSOCKS5At(t testing.TB, addr, user, pass string) *SOCKS5Server {
	t.Helper()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen socks5: %v", err)
	}

	s := &SOCKS5Server{Addr: mustAddrPort(t, ln.Addr()), ln: ln, user: user, pass: pass}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.accepted.Add(1)
			s.track(conn)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.serve(conn)
			}()
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
		// Sessions outlive the request that created them (a UDP association
		// lives as long as its control connection), so close them explicitly
		// rather than waiting for the engine's idle timeouts.
		s.closeAll()
		s.wg.Wait()
	})

	return s
}

// track registers a connection to be closed when the server shuts down.
func (s *SOCKS5Server) track(c io.Closer) {
	s.mu.Lock()
	s.closers = append(s.closers, c)
	s.mu.Unlock()
}

func (s *SOCKS5Server) closeAll() {
	s.mu.Lock()
	closers := s.closers
	s.closers = nil
	s.mu.Unlock()

	for _, c := range closers {
		_ = c.Close()
	}
}

// Destinations returns a copy of the destinations requested so far.
func (s *SOCKS5Server) Destinations() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.Requested...)
}

func (s *SOCKS5Server) record(dst string) {
	s.mu.Lock()
	s.Requested = append(s.Requested, dst)
	s.mu.Unlock()
}

// dial returns the address to actually connect to for a requested destination.
func (s *SOCKS5Server) dial(dst string) string {
	if s.Upstream.IsValid() {
		return s.Upstream.String()
	}
	return dst
}

func (s *SOCKS5Server) serve(conn net.Conn) {
	defer conn.Close()

	if err := s.handshake(conn); err != nil {
		return
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	head := make([]byte, 3)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}

	dst, err := readSocksAddr(conn)
	if err != nil {
		return
	}

	switch head[1] {
	case 0x01: // CONNECT
		s.record(dst)
		s.connect(conn, dst)
	case 0x03: // UDP ASSOCIATE
		s.udpAssociate(conn)
	default:
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

func (s *SOCKS5Server) handshake(conn net.Conn) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != 0x05 {
		return errors.New("bad socks version")
	}

	methods := make([]byte, head[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	wantUser, wantPass := s.auth()
	if wantUser == "" {
		_, err := conn.Write([]byte{0x05, 0x00})
		return err
	}

	if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
		return err
	}

	// Auth: VER ULEN UNAME PLEN PASSWD
	verLen := make([]byte, 2)
	if _, err := io.ReadFull(conn, verLen); err != nil {
		return err
	}
	user := make([]byte, verLen[1])
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return err
	}
	pass := make([]byte, plen[0])
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}

	if string(user) != wantUser || string(pass) != wantPass {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return errors.New("bad credentials")
	}

	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

func (s *SOCKS5Server) connect(client net.Conn, dst string) {
	remote, err := net.Dial("tcp", s.dial(dst))
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	if _, err = client.Write(replyWithAddr(remote.LocalAddr())); err != nil {
		return
	}

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(remote, client)
		if tcpConn, ok := remote.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(client, remote)
	<-done
}

// udpAssociate opens a relay socket, tells the client about it and relays
// datagrams until the control connection goes away.
func (s *SOCKS5Server) udpAssociate(control net.Conn) {
	relay, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		_, _ = control.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer relay.Close()
	s.track(relay)

	if _, err = control.Write(replyWithAddr(relay.LocalAddr())); err != nil {
		return
	}

	go func() {
		// A UDP association terminates when its control connection does.
		_, _ = io.Copy(io.Discard, control)
		_ = relay.Close()
	}()

	s.relayUDP(relay)
}

func (s *SOCKS5Server) relayUDP(relay net.PacketConn) {
	// Sockets towards the real destinations, one per client/destination pair.
	upstreams := make(map[string]net.PacketConn)
	defer func() {
		for _, pc := range upstreams {
			_ = pc.Close()
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, client, err := relay.ReadFrom(buf)
		if err != nil {
			return
		}

		dst, payload, err := decodeUDPRequest(buf[:n])
		if err != nil {
			continue
		}
		s.record(dst)

		key := client.String() + "|" + dst
		up, ok := upstreams[key]
		if !ok {
			up, err = net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				continue
			}
			upstreams[key] = up

			go func(up net.PacketConn, client net.Addr, dst string) {
				rbuf := make([]byte, 65535)
				for {
					rn, _, err := up.ReadFrom(rbuf)
					if err != nil {
						return
					}
					packet, err := encodeUDPReply(dst, rbuf[:rn])
					if err != nil {
						continue
					}
					if _, err = relay.WriteTo(packet, client); err != nil {
						return
					}
				}
			}(up, client, dst)
		}

		dstAddr, err := net.ResolveUDPAddr("udp", s.dial(dst))
		if err != nil {
			continue
		}
		if _, err = up.WriteTo(payload, dstAddr); err != nil {
			continue
		}
	}
}

func mustAddrPort(t testing.TB, addr net.Addr) netip.AddrPort {
	t.Helper()

	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		t.Fatalf("parse addr %s: %v", addr, err)
	}

	return ap
}

// BulkTCP starts a TCP server on loopback that writes size bytes to every
// connection and then closes it.
//
// It is the source for throughput benchmarks. The console downloads, so the
// engine's stack is the sender and its congestion control is what the numbers
// measure.
func BulkTCP(t testing.TB, size int) netip.AddrPort {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen bulk tcp: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	payload := make([]byte, 64<<10)
	for i := range payload {
		payload[i] = byte(i)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				for sent := 0; sent < size; {
					chunk := payload
					if remaining := size - sent; remaining < len(chunk) {
						chunk = chunk[:remaining]
					}
					n, err := conn.Write(chunk)
					if err != nil {
						return
					}
					sent += n
				}
			}()
		}
	}()

	return mustAddrPort(t, ln.Addr())
}
