package e2e

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

// Address helpers for the test SOCKS5 server (RFC 1928 section 5 / 7).

func readSocksAddr(r io.Reader) (string, error) {
	atyp := make([]byte, 1)
	if _, err := io.ReadFull(r, atyp); err != nil {
		return "", err
	}

	var host string
	switch atyp[0] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = string(b)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	default:
		return "", errors.New("unknown address type")
	}

	p := make([]byte, 2)
	if _, err := io.ReadFull(r, p); err != nil {
		return "", err
	}

	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p)))), nil
}

// replyWithAddr builds a success reply carrying addr as BND.ADDR/BND.PORT.
func replyWithAddr(addr net.Addr) []byte {
	reply := []byte{0x05, 0x00, 0x00}
	return append(reply, serializeAddr(addr.String())...)
}

func serializeAddr(hostport string) []byte {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return []byte{0x01, 0, 0, 0, 0, 0, 0}
	}
	port, _ := strconv.ParseUint(portStr, 10, 16)

	ip := net.ParseIP(host)
	switch {
	case ip == nil:
		out := append([]byte{0x03, byte(len(host))}, host...)
		return binary.BigEndian.AppendUint16(out, uint16(port))
	case ip.To4() != nil:
		out := append([]byte{0x01}, ip.To4()...)
		return binary.BigEndian.AppendUint16(out, uint16(port))
	default:
		out := append([]byte{0x04}, ip.To16()...)
		return binary.BigEndian.AppendUint16(out, uint16(port))
	}
}

// decodeUDPRequest parses a SOCKS5 UDP request: RSV(2) FRAG(1) ADDR PORT DATA.
func decodeUDPRequest(packet []byte) (dst string, payload []byte, err error) {
	if len(packet) < 4 {
		return "", nil, errors.New("short udp packet")
	}
	if packet[2] != 0 {
		return "", nil, errors.New("fragmented udp packet")
	}

	rest := packet[3:]
	consumed, dst, err := parseAddrLen(rest)
	if err != nil {
		return "", nil, err
	}

	return dst, rest[consumed:], nil
}

// encodeUDPReply wraps payload as a SOCKS5 UDP reply from dst.
func encodeUDPReply(dst string, payload []byte) ([]byte, error) {
	packet := []byte{0x00, 0x00, 0x00}
	packet = append(packet, serializeAddr(dst)...)
	return append(packet, payload...), nil
}

func parseAddrLen(b []byte) (int, string, error) {
	if len(b) < 1 {
		return 0, "", errors.New("short address")
	}

	var (
		host string
		n    int
	)

	switch b[0] {
	case 0x01:
		if len(b) < 1+4+2 {
			return 0, "", errors.New("short ipv4 address")
		}
		host = net.IP(b[1:5]).String()
		n = 1 + 4
	case 0x03:
		if len(b) < 2 {
			return 0, "", errors.New("short domain address")
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return 0, "", errors.New("short domain address")
		}
		host = string(b[2 : 2+l])
		n = 2 + l
	case 0x04:
		if len(b) < 1+16+2 {
			return 0, "", errors.New("short ipv6 address")
		}
		host = net.IP(b[1:17]).String()
		n = 1 + 16
	default:
		return 0, "", errors.New("unknown address type")
	}

	port := binary.BigEndian.Uint16(b[n : n+2])

	return n + 2, net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}
