package proxy

import "fmt"

const (
	ModeDirect Mode = iota
	ModeSocks5
	ModeRouter
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
	default:
		return fmt.Sprintf("proto(%d)", mode)
	}
}
