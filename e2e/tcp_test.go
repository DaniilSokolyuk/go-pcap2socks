package e2e

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDst is the address the fake console dials. It is a documentation address
// (RFC 5737 TEST-NET-3): the console cannot route to loopback, so tests target
// this and let the test SOCKS5 server redirect to the real echo server.
var fakeDst = netip.MustParseAddrPort("203.0.113.10:80")

// socksHarness starts an echo server, a SOCKS5 server pointing at it and an
// engine whose only outbound is that SOCKS5 server.
func socksHarness(t *testing.T, user, pass string) (*Harness, *SOCKS5Server) {
	t.Helper()

	echo := EchoTCP(t)
	socks := StartSOCKS5(t, user, pass)
	socks.Upstream = echo

	h := Start(t, NewConfig().Socks("", socks.Addr, user, pass).Build(t))

	return h, socks
}

// TestTCPThroughSocks5 walks a TCP connection from the fake console all the way
// to a real server: console -> ethernet -> gVisor -> tunnel -> router -> socks5.
func TestTCPThroughSocks5(t *testing.T) {
	h, socks := socksHarness(t, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := h.Client.DialTCP(ctx, fakeDst)
	require.NoError(t, err, "dial through the stack")
	defer conn.Close()

	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	want := []byte("hello console")
	_, err = conn.Write(want)
	require.NoError(t, err)

	got := make([]byte, len(want))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	// The destination the console asked for must survive to the proxy intact.
	assert.Equal(t, []string{fakeDst.String()}, socks.Destinations())
}

// TestTCPWithSocks5Auth checks username/password authentication is performed.
func TestTCPWithSocks5Auth(t *testing.T) {
	h, _ := socksHarness(t, "user", "secret")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := h.Client.DialTCP(ctx, fakeDst)
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	_, err = conn.Write([]byte("x"))
	require.NoError(t, err)

	got := make([]byte, 1)
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	assert.Equal(t, []byte("x"), got)
}

// TestTCPBadSocks5Credentials checks a rejected handshake does not hang.
func TestTCPBadSocks5Credentials(t *testing.T) {
	echo := EchoTCP(t)
	socks := StartSOCKS5(t, "user", "secret")
	socks.Upstream = echo

	h := Start(t, NewConfig().Socks("", socks.Addr, "user", "wrong").Build(t))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := h.Client.DialTCP(ctx, fakeDst)
	require.NoError(t, err, "the stack completes its handshake before dialling out")
	defer conn.Close()

	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	// The tunnel closes the connection once the outbound dial fails.
	got, err := io.ReadAll(conn)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestTCPHalfClose checks that a client half-close is propagated to the remote
// side and the response still arrives.
func TestTCPHalfClose(t *testing.T) {
	h, _ := socksHarness(t, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := h.Client.DialTCP(ctx, fakeDst)
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	want := []byte("half closed")
	_, err = conn.Write(want)
	require.NoError(t, err)

	closer, ok := conn.(interface{ CloseWrite() error })
	require.True(t, ok, "gonet TCPConn should support CloseWrite")
	require.NoError(t, closer.CloseWrite())

	// The echo server sees EOF, echoes what it had and closes; we must read the
	// payload and then EOF rather than hanging.
	got, err := io.ReadAll(conn)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// TestTCPLargeTransfer pushes far more than one window through the relay.
func TestTCPLargeTransfer(t *testing.T) {
	h, _ := socksHarness(t, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := h.Client.DialTCP(ctx, fakeDst)
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.SetDeadline(time.Now().Add(60*time.Second)))

	payload := make([]byte, 1<<20) // 1 MiB
	for i := range payload {
		payload[i] = byte(i)
	}

	done := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		done <- err
	}()

	got := make([]byte, len(payload))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.NoError(t, <-done)
	assert.True(t, assert.ObjectsAreEqual(payload, got), "payload survived the round trip")
}

// TestTCPReject checks the reject outbound closes the connection immediately.
func TestTCPReject(t *testing.T) {
	h := Start(t, NewConfig().Reject("").Build(t))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := h.Client.DialTCP(ctx, fakeDst)
	require.NoError(t, err, "reject still completes the handshake")
	defer conn.Close()

	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	got, err := io.ReadAll(conn)
	require.NoError(t, err)
	assert.Empty(t, got)
}
