package device

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/sys/windows"
)

// Npcap's send queue: frames are copied into a queue in user space and handed
// to the driver in one call, instead of one pcap_sendpacket per frame. This is
// the Windows counterpart of sendmmsg on Linux.
var (
	wpcap = windows.NewLazyDLL("wpcap.dll") // already loaded by gopacket

	procSendQueueAlloc    = wpcap.NewProc("pcap_sendqueue_alloc")
	procSendQueueQueue    = wpcap.NewProc("pcap_sendqueue_queue")
	procSendQueueTransmit = wpcap.NewProc("pcap_sendqueue_transmit")
	procSendQueueDestroy  = wpcap.NewProc("pcap_sendqueue_destroy")
)

// sendQueueHeader is struct pcap_pkthdr as Windows lays it out: a timeval of
// two 32 bit longs, then the captured and original lengths. It matches
// gopacket's own definition in pcap/defs_windows.go.
type sendQueueHeader struct {
	sec, usec int32
	caplen    uint32
	length    uint32
}

type queueSender struct {
	mu     sync.Mutex
	handle *pcap.Handle
	pcapT  uintptr
	// header lives on the heap so that its address stays put for the
	// duration of a call.
	header *sendQueueHeader
}

func newPcapFrameSender(handle *pcap.Handle) (frameSender, error) {
	for _, proc := range []*windows.LazyProc{
		procSendQueueAlloc, procSendQueueQueue, procSendQueueTransmit, procSendQueueDestroy,
	} {
		if err := proc.Find(); err != nil {
			return nil, fmt.Errorf("%s: %w", proc.Name, err)
		}
	}

	// The queue is transmitted on the capture handle itself, and gopacket
	// keeps the underlying pcap_t in an unexported field. Reading it is the
	// alternative to opening the adapter a second time just to send.
	field := reflect.ValueOf(handle).Elem().FieldByName("cptr")
	if !field.IsValid() || field.Kind() != reflect.Uintptr || field.Uint() == 0 {
		return nil, errors.New("gopacket no longer exposes the pcap handle the way this expects")
	}

	return &queueSender{
		handle: handle,
		pcapT:  uintptr(field.Uint()),
		header: new(sendQueueHeader),
	}, nil
}

func (s *queueSender) send(frames [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	const headerSize = unsafe.Sizeof(sendQueueHeader{})
	var size uintptr
	for _, frame := range frames {
		if len(frame) > 0 {
			size += headerSize + uintptr(len(frame))
		}
	}
	if size == 0 {
		return nil
	}

	queue, _, _ := syscall.SyscallN(procSendQueueAlloc.Addr(), size)
	if queue == 0 {
		return errors.New("pcap_sendqueue_alloc failed")
	}
	defer syscall.SyscallN(procSendQueueDestroy.Addr(), queue)

	for _, frame := range frames {
		if len(frame) == 0 {
			continue
		}
		*s.header = sendQueueHeader{caplen: uint32(len(frame)), length: uint32(len(frame))}
		ret, _, _ := syscall.SyscallN(procSendQueueQueue.Addr(),
			queue, uintptr(unsafe.Pointer(s.header)), uintptr(unsafe.Pointer(&frame[0])))
		if int32(ret) != 0 {
			return errors.New("pcap_sendqueue_queue failed")
		}
	}
	runtime.KeepAlive(frames)

	// sync = 0: send as fast as possible, ignoring the timestamps.
	ret, _, _ := syscall.SyscallN(procSendQueueTransmit.Addr(), s.pcapT, queue, 0)
	// The function returns a 32 bit count; the rest of the register is noise.
	sent := uintptr(uint32(ret))
	if sent < size {
		return fmt.Errorf("pcap_sendqueue_transmit sent %d of %d bytes: %w", sent, size, s.handle.Error())
	}
	return nil
}

func (s *queueSender) close() error { return nil }
