package proxy

import (
	"context"
	"errors"
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
	cfg       cfg.DNS
	dnsClient *dns.Client
	// local resolves through the system's own DNS servers, for the "local"
	// server. One client for the whole outbound, so the system is not asked
	// for its configuration on every query.
	local localdns.LocalClient
}

func (d *DNS) Addr() string {
	return "dns"
}

func (d *DNS) Mode() Mode {
	return ModeDNS
}

func NewDNS(cfg cfg.DNS) *DNS {
	dnsClient := new(dns.Client)
	dnsClient.UDPSize = math.MaxUint16

	return &DNS{
		dnsClient: dnsClient,
		cfg:       cfg,
		local:     localdns.NewLocalClient(),
	}
}

func (d *DNS) DialContext(_ context.Context, _ *M.Metadata) (net.Conn, error) {
	return &nopConn{}, nil
}

func (d *DNS) DialUDP(m *M.Metadata) (net.PacketConn, error) {
	return &dnsConn{
		cfg:          d.cfg,
		m:            m,
		dnsClient:    d.dnsClient,
		local:        d.local,
		answerCh:     make(chan dnsAnswer, 1),
		done:         make(chan struct{}),
		readDeadline: pipe.MakeDeadline(),
	}, nil
}

// dnsAnswer is a response and the resolver the device addressed its query to.
// One session carries queries to several resolvers - a UDP session is keyed
// on the device's own address only - and each answer has to appear to come
// from the one that was asked, or the device discards it.
type dnsAnswer struct {
	msg  *dns.Msg
	from net.Addr
}

type dnsConn struct {
	dnsClient *dns.Client
	local     localdns.LocalClient
	answerCh  chan dnsAnswer
	m         *M.Metadata
	cfg       cfg.DNS

	done         chan struct{}
	closeOnce    sync.Once
	readDeadline pipe.Deadline
}

func (d *dnsConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	select {
	case answer := <-d.answerCh:
		packed, err := answer.msg.PackBuffer(b)
		if err != nil {
			return 0, nil, err
		}
		// PackBuffer may allocate a new slice when b is too small; copy is a
		// no-op when it packed in place.
		return copy(b, packed), answer.from, nil
	case <-d.done:
		return 0, nil, net.ErrClosed
	case <-d.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (d *dnsConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	msg := new(dns.Msg)
	err = msg.Unpack(b)
	if err != nil {
		return 0, err
	}

	if addr == nil {
		addr = d.m.UDPAddr()
	}
	go d.exchange(msg, addr)
	return len(b), nil
}

// exchange resolves msg against the configured servers and hands the answer to
// ReadFrom. It always returns once the connection is closed, so a session that
// goes away mid-query does not leak this goroutine.
func (d *dnsConn) exchange(msg *dns.Msg, from net.Addr) {
	response, err := d.resolve(msg)
	if err != nil {
		slog.Error("all dns servers failed", slog.Any("err", err))
		// Say so, rather than leave the device waiting for its own timeout
		// before it tries anything else.
		response = new(dns.Msg)
		response.SetRcode(msg, dns.RcodeServerFailure)
	}

	select {
	case d.answerCh <- dnsAnswer{msg: response, from: from}:
	case <-d.done:
	}
}

// resolve tries the configured servers in order; the first answer wins.
func (d *dnsConn) resolve(msg *dns.Msg) (*dns.Msg, error) {
	lastErr := errors.New("no dns servers configured")
	for _, server := range d.cfg.Servers {
		var (
			response *dns.Msg
			err      error
		)
		if server.Address == "local" {
			response, err = d.local.Exchange(msg)
		} else {
			response, _, err = d.dnsClient.Exchange(msg, server.Address)
		}
		if err == nil {
			return response, nil
		}
		slog.Warn("dns exchange failed", slog.String("server", server.Address), slog.Any("err", err))
		lastErr = err
	}
	return nil, lastErr
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
