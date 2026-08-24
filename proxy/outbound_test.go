package proxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	M "github.com/DaniilSokolyuk/go-pcap2socks/md"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// echoTCP starts a loopback TCP echo server.
func echoTCP(t *testing.T) *net.TCPAddr {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
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

	return ln.Addr().(*net.TCPAddr)
}

// echoUDP starts a loopback UDP echo server.
func echoUDP(t *testing.T) *net.UDPAddr {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 2048)
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

	return pc.LocalAddr().(*net.UDPAddr)
}

func mdFor(addr net.Addr, network M.Network) *M.Metadata {
	md := &M.Metadata{Network: network, SrcIP: net.IPv4(172, 26, 0, 5), SrcPort: 40000}

	switch v := addr.(type) {
	case *net.TCPAddr:
		md.DstIP, md.DstPort = v.IP, uint16(v.Port)
	case *net.UDPAddr:
		md.DstIP, md.DstPort = v.IP, uint16(v.Port)
	}

	return md
}

func TestDirectTCP(t *testing.T) {
	addr := echoTCP(t)

	conn, err := NewDirect().DialContext(context.Background(), mdFor(addr, M.TCP))
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	_, err = conn.Write([]byte("direct"))
	require.NoError(t, err)

	got := make([]byte, 6)
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	assert.Equal(t, "direct", string(got))
}

func TestDirectTCPRefused(t *testing.T) {
	// Grab a port and immediately release it so nothing is listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().(*net.TCPAddr)
	require.NoError(t, ln.Close())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = NewDirect().DialContext(ctx, mdFor(addr, M.TCP))
	require.Error(t, err)
}

func TestDirectUDP(t *testing.T) {
	addr := echoUDP(t)

	pc, err := NewDirect().DialUDP(mdFor(addr, M.UDP))
	require.NoError(t, err)
	defer pc.Close()

	require.NoError(t, pc.SetDeadline(time.Now().Add(5*time.Second)))

	_, err = pc.WriteTo([]byte("direct udp"), addr)
	require.NoError(t, err)

	buf := make([]byte, 64)
	n, from, err := pc.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "direct udp", string(buf[:n]))
	assert.Equal(t, addr.String(), from.String())
}

// TestDirectUDPWritesToMetadataAddr checks the metadata address (which is not a
// *net.UDPAddr) is resolved rather than rejected.
func TestDirectUDPWritesToMetadataAddr(t *testing.T) {
	addr := echoUDP(t)
	md := mdFor(addr, M.UDP)

	pc, err := NewDirect().DialUDP(md)
	require.NoError(t, err)
	defer pc.Close()

	require.NoError(t, pc.SetDeadline(time.Now().Add(5*time.Second)))

	_, err = pc.WriteTo([]byte("via metadata"), md.Addr())
	require.NoError(t, err)

	buf := make([]byte, 64)
	n, _, err := pc.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "via metadata", string(buf[:n]))
}

func TestReject(t *testing.T) {
	md := metadata("172.26.0.5", 40000, "1.1.1.1", 443)

	conn, err := NewReject().DialContext(context.Background(), md)
	require.NoError(t, err)

	n, err := conn.Read(make([]byte, 8))
	assert.Zero(t, n)
	assert.ErrorIs(t, err, io.EOF)
	assert.NoError(t, conn.Close())

	pc, err := NewReject().DialUDP(md)
	require.NoError(t, err)

	n, err = pc.WriteTo([]byte("swallowed"), md.UDPAddr())
	assert.Equal(t, 9, n, "writes are accepted and dropped")
	assert.NoError(t, err)

	_, _, err = pc.ReadFrom(make([]byte, 8))
	assert.ErrorIs(t, err, io.EOF)
	assert.NoError(t, pc.Close())
}

func TestDNSOutbound(t *testing.T) {
	upstream := startDNSServer(t, net.IPv4(198, 51, 100, 7))

	p := NewDNS(cfg.DNS{Servers: []struct {
		Address string `json:"address"`
	}{{Address: upstream}}}, "")

	md := &M.Metadata{Network: M.UDP, DstIP: net.IPv4(1, 1, 1, 1), DstPort: 53}
	pc, err := p.DialUDP(md)
	require.NoError(t, err)
	defer pc.Close()

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	packed, err := query.Pack()
	require.NoError(t, err)

	_, err = pc.WriteTo(packed, md.UDPAddr())
	require.NoError(t, err)

	require.NoError(t, pc.SetReadDeadline(time.Now().Add(5*time.Second)))

	buf := make([]byte, 4096)
	n, from, err := pc.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, md.UDPAddr().String(), from.String())

	resp := new(dns.Msg)
	require.NoError(t, resp.Unpack(buf[:n]))
	require.Len(t, resp.Answer, 1)
	assert.Equal(t, "198.51.100.7", resp.Answer[0].(*dns.A).A.String())
}

// TestDNSOutboundReadDeadline pins the fix for the connection that used to
// ignore deadlines and block forever when no answer arrived.
func TestDNSOutboundReadDeadline(t *testing.T) {
	p := NewDNS(cfg.DNS{}, "")

	pc, err := p.DialUDP(&M.Metadata{Network: M.UDP, DstIP: net.IPv4(1, 1, 1, 1), DstPort: 53})
	require.NoError(t, err)
	defer pc.Close()

	require.NoError(t, pc.SetReadDeadline(time.Now().Add(200*time.Millisecond)))

	start := time.Now()
	_, _, err = pc.ReadFrom(make([]byte, 512))
	require.Error(t, err)
	assert.Less(t, time.Since(start), 3*time.Second, "the read must honour its deadline")
}

// TestDNSOutboundCloseUnblocksRead checks closing the session wakes a pending
// reader instead of stranding it.
func TestDNSOutboundCloseUnblocksRead(t *testing.T) {
	p := NewDNS(cfg.DNS{}, "")

	pc, err := p.DialUDP(&M.Metadata{Network: M.UDP, DstIP: net.IPv4(1, 1, 1, 1), DstPort: 53})
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		_, _, err := pc.ReadFrom(make([]byte, 512))
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	require.NoError(t, pc.Close())

	select {
	case err := <-done:
		assert.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(3 * time.Second):
		t.Fatal("closing the connection must unblock the reader")
	}
}

func startDNSServer(t *testing.T, answer net.IP) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			for _, q := range req.Question {
				rr, err := dns.NewRR(q.Name + " 60 IN A " + answer.String())
				if err == nil {
					resp.Answer = append(resp.Answer, rr)
				}
			}
			_ = w.WriteMsg(resp)
		}),
	}

	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started

	t.Cleanup(func() { _ = srv.Shutdown() })

	return pc.LocalAddr().String()
}
