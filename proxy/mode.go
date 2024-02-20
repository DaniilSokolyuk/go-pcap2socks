package proxy

import "fmt"

const (
	ModeDirect Mode = iota
	ModeSocks5
	ModeRouter
	ModeReject
)

type Mode uint8

func (mode Mode) String() string {
	switch mode {
	case ModeRouter:
		return "router"
	case ModeDirect:
		return "direct"
	case ModeSocks5:
		return "socks5"
	case ModeReject:
		return "reject"
	default:
		return fmt.Sprintf("proto(%d)", mode)
	}
}
