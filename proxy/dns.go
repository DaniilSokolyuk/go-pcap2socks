package proxy

import (
	"context"
	"log/slog"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	localdns "github.com/DaniilSokolyuk/go-pcap2socks/dns"
	M "github.com/DaniilSokolyuk/go-pcap2socks/md"
	"github.com/miekg/dns"
	"github.com/sagernet/sing/common/pipe"
)

var _ Proxy = (*DNS)(nil)

type DNS struct {
	cfg           cfg.DNS
	dnsClient     *dns.Client
	interfaceName string
}

func (d *DNS) Addr() string {
	return "dns"
}

func (d *DNS) Mode() Mode {
	return ModeDNS
}

func NewDNS(cfg cfg.DNS, interfaceName string) *DNS {
	dnsClient := new(dns.Client)
	dnsClient.UDPSize = math.MaxUint16

	return &DNS{
		dnsClient:     dnsClient,
		cfg:           cfg,
		interfaceName: interfaceName,
	}
}

func (d *DNS) DialContext(_ context.Context, _ *M.Metadata) (net.Conn, error) {
	return &nopConn{}, nil
}

func (d *DNS) DialUDP(m *M.Metadata) (net.PacketConn, error) {
	return &dnsConn{
		cfg:           d.cfg,
		m:             m,
		dnsClient:     d.dnsClient,
		answerCh:      make(chan *dns.Msg, 1),
		done:          make(chan struct{}),
		readDeadline:  pipe.MakeDeadline(),
		interfaceName: d.interfaceName,
	}, nil
}

type dnsConn struct {
	dnsClient     *dns.Client
	answerCh      chan *dns.Msg
	m             *M.Metadata
	cfg           cfg.DNS
	interfaceName string

	done         chan struct{}
	closeOnce    sync.Once
	readDeadline pipe.Deadline
}

func (d *dnsConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	select {
	case msg := <-d.answerCh:
		packed, err := msg.PackBuffer(b)
		if err != nil {
			return 0, nil, err
		}
		// PackBuffer may allocate a new slice when b is too small; copy is a
		// no-op when it packed in place.
		return copy(b, packed), d.m.UDPAddr(), nil
	case <-d.done:
		return 0, nil, net.ErrClosed
	case <-d.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (d *dnsConn) WriteTo(b []byte, _ net.Addr) (n int, err error) {
	msg := new(dns.Msg)
	err = msg.Unpack(b)
	if err != nil {
		return 0, err
	}

	go d.exchange(msg)

	return len(b), nil
}

// exchange resolves msg against the configured servers and hands the answer to
// ReadFrom. It always returns once the connection is closed, so a session that
// goes away mid-query does not leak this goroutine.
func (d *dnsConn) exchange(msg *dns.Msg) {
	var lastErr error

	for _, server := range d.cfg.Servers {
		var response *dns.Msg

		if server.Address == "local" {
			localClient := localdns.NewLocalClient(d.interfaceName)
			response, lastErr = localClient.Exchange(msg)
			if lastErr != nil {
				slog.Error("local dns exchange failed", slog.Any("err", lastErr))
				continue
			}
		} else {
			response, _, lastErr = d.dnsClient.Exchange(msg, server.Address)
			if lastErr != nil {
				slog.Error("dns exchange failed", slog.String("server", server.Address), slog.Any("err", lastErr))
				continue
			}
		}

		select {
		case d.answerCh <- response:
		case <-d.done:
		}
		return
	}

	if lastErr != nil {
		slog.Error("all dns servers failed", slog.Any("err", lastErr))
	}
}

func (d *dnsConn) Close() error {
	d.closeOnce.Do(func() {
		close(d.done)
	})
	return nil
}

func (d *dnsConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

func (d *dnsConn) SetDeadline(t time.Time) error {
	d.readDeadline.Set(t)
	return nil
}

func (d *dnsConn) SetReadDeadline(t time.Time) error {
	d.readDeadline.Set(t)
	return nil
}

func (d *dnsConn) SetWriteDeadline(time.Time) error {
	return nil
}
