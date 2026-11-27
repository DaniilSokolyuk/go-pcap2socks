package device

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/net/bpf"
)

// Offsets into an untagged ethernet frame.
const (
	offEtherType = 12
	offIPv4Proto = 14 + 9
	offIPv4Src   = 14 + 12
	offIPv4Dst   = 14 + 16
	offARPSender = 14 + 14 // sender protocol address
	offARPTarget = 14 + 24 // target protocol address

	etherTypeIPv4 = 0x0800
	etherTypeARP  = 0x0806
	protoICMP     = 1
)

// CaptureFilter is the capture filter as a classic BPF program, for the Linux
// source, which attaches it to a socket itself. BPFFilter is the same filter
// as text for libpcap; a change to one belongs in both. It accepts the same traffic the device goes on to use:
//
//   - ARP addressed to the gateway, from the network, not from the gateway;
//   - IPv4 from the network to anywhere outside it, except the gateway's own
//     ICMP.
//
// It is narrower than the text filter in one respect: libpcap's unqualified
// "src net" also matches ARP sender addresses, so the text form lets through
// ARP from the network for targets outside it. The device drops those anyway.
func CaptureFilter(netConfig *NetworkConfig) ([]bpf.RawInstruction, error) {
	gatewayIP := netConfig.LocalIP.To4()
	networkIP := netConfig.Network.IP.To4()
	if gatewayIP == nil || networkIP == nil || len(netConfig.Network.Mask) != 4 {
		return nil, fmt.Errorf("capture filter needs an IPv4 network and gateway")
	}
	gateway := binary.BigEndian.Uint32(gatewayIP)
	mask := binary.BigEndian.Uint32(netConfig.Network.Mask)
	network := binary.BigEndian.Uint32(networkIP) & mask

	var p program
	p.add(bpf.LoadAbsolute{Off: offEtherType, Size: 2})
	p.jump(etherTypeARP, "arp", "")
	p.jump(etherTypeIPv4, "", "drop")

	// IPv4: from the network...
	p.add(bpf.LoadAbsolute{Off: offIPv4Src, Size: 4})
	p.add(bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: mask})
	p.jump(network, "", "drop")
	// ...to somewhere outside it...
	p.add(bpf.LoadAbsolute{Off: offIPv4Dst, Size: 4})
	p.add(bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: mask})
	p.jump(network, "drop", "")
	// ...and not ICMP we sent ourselves, which promiscuous capture would
	// otherwise feed back in.
	p.add(bpf.LoadAbsolute{Off: offIPv4Proto, Size: 1})
	p.jump(protoICMP, "", "accept")
	p.add(bpf.LoadAbsolute{Off: offIPv4Src, Size: 4})
	p.jump(gateway, "drop", "accept")

	// ARP: for the gateway, not from it, from the network.
	p.label("arp")
	p.add(bpf.LoadAbsolute{Off: offARPTarget, Size: 4})
	p.jump(gateway, "", "drop")
	p.add(bpf.LoadAbsolute{Off: offARPSender, Size: 4})
	p.jump(gateway, "drop", "")
	p.add(bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: mask})
	p.jump(network, "", "drop")

	p.label("accept")
	p.add(bpf.RetConstant{Val: 0x40000})
	p.label("drop")
	p.add(bpf.RetConstant{Val: 0})

	return p.assemble()
}

// program is a list of BPF instructions whose conditional jumps name their
// targets, so nobody has to count instructions by hand.
type program struct {
	instructions []bpf.Instruction
	labels       map[string]int
	jumps        []pendingJump
}

type pendingJump struct {
	at            int
	value         uint32
	ifTrue, ifNot string // "" means fall through
}

func (p *program) add(instruction bpf.Instruction) {
	p.instructions = append(p.instructions, instruction)
}

func (p *program) label(name string) {
	if p.labels == nil {
		p.labels = make(map[string]int)
	}
	p.labels[name] = len(p.instructions)
}

// jump compares the accumulator with value.
func (p *program) jump(value uint32, ifTrue, ifNot string) {
	p.jumps = append(p.jumps, pendingJump{at: len(p.instructions), value: value, ifTrue: ifTrue, ifNot: ifNot})
	p.add(nil)
}

func (p *program) assemble() ([]bpf.RawInstruction, error) {
	skip := func(from int, target string) (uint8, error) {
		if target == "" {
			return 0, nil
		}
		to, ok := p.labels[target]
		if !ok {
			return 0, fmt.Errorf("undefined label %q", target)
		}
		distance := to - (from + 1)
		if distance < 0 || distance > 255 {
			return 0, fmt.Errorf("jump to %q out of range", target)
		}
		return uint8(distance), nil
	}
	for _, j := range p.jumps {
		onTrue, err := skip(j.at, j.ifTrue)
		if err != nil {
			return nil, err
		}
		onFalse, err := skip(j.at, j.ifNot)
		if err != nil {
			return nil, err
		}
		p.instructions[j.at] = bpf.JumpIf{Cond: bpf.JumpEqual, Val: j.value, SkipTrue: onTrue, SkipFalse: onFalse}
	}
	return bpf.Assemble(p.instructions)
}

// BPFFilter builds the capture filter for the configured network.
//
// 1. ARP packets: (arp dst host <localIP> and arp src net <network> and not arp src host <localIP>)
//   - Only ARP requests TO us (arp dst host)
//   - From devices in our network (arp src net)
//   - Not from ourselves (not arp src host) - loop prevention
//
// 2. IPv4 packets: (src net <network> and not dst net <network> and not (icmp and src host <localIP>))
//   - All IPv4 packets from the configured network
//   - Not destined to the local network (only capture internet-bound traffic)
//   - Exclude ICMP from ourselves (loop prevention in promiscuous mode)
//
// ARP field access in BPF:
//   - "arp src host X" / "arp src net X" - checks Source Protocol Address (SPA) field
//   - "arp dst host X" / "arp dst net X" - checks Target Protocol Address (TPA) field
func BPFFilter(netConfig *NetworkConfig) string {
	return fmt.Sprintf(
		"(arp dst host %s and arp src net %s and not arp src host %s) or (src net %s and not dst net %s and not (icmp and src host %s))",
		netConfig.LocalIP.String(),
		netConfig.Network.String(),
		netConfig.LocalIP.String(),
		netConfig.Network.String(),
		netConfig.Network.String(),
		netConfig.LocalIP.String(),
	)
}
