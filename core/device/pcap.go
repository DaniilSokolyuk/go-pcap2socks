package device

import (
	"fmt"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/device/iobased"
	"io"
	"net"
	"sync"
)

type TUN struct {
	*iobased.Endpoint

	nt     io.ReadWriteCloser
	mtu    uint32
	name   string
	offset int

	rMutex sync.Mutex
	wMutex sync.Mutex
}

const offset = 0

func Open(name string, mtu uint32, pcap io.ReadWriteCloser, mac net.HardwareAddr) (_ Device, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("open tun: %v", r)
		}
	}()

	t := &TUN{
		name:   name,
		mtu:    mtu,
		offset: offset,
		nt:     pcap,
	}

	ep, err := iobased.New(pcap, t.mtu, offset, mac)
	if err != nil {
		return nil, fmt.Errorf("create endpoint: %w", err)
	}
	t.Endpoint = ep

	return t, nil
}

func (t *TUN) Read(packet []byte) (int, error) {
	t.rMutex.Lock()
	defer t.rMutex.Unlock()
	return t.nt.Read(packet)
}

func (t *TUN) Write(packet []byte) (int, error) {
	t.wMutex.Lock()
	defer t.wMutex.Unlock()
	return t.nt.Write(packet)
}

func (t *TUN) Name() string {
	return t.Name()
}

func (t *TUN) Close() error {
	defer t.Endpoint.Close()
	return t.nt.Close()
}

const pcap = "pcap"

func (t *TUN) Type() string {
	return pcap
}
