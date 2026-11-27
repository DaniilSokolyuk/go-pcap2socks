package device

import (
	"errors"
	"fmt"
	"io"
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
type sendQueueProcs struct {
	alloc, queue, transmit, destroy uintptr
}

// loadSendQueueProcs resolves the functions from the wpcap.dll gopacket has
// already loaded. Looking the module up by handle, rather than loading it by
// name again, cannot pick up a different DLL from another directory.
func loadSendQueueProcs() (*sendQueueProcs, error) {
	name, err := windows.UTF16PtrFromString("wpcap.dll")
	if err != nil {
		return nil, err
	}
	var module windows.Handle
	if err = windows.GetModuleHandleEx(0, name, &module); err != nil {
		return nil, fmt.Errorf("wpcap.dll is not loaded: %w", err)
	}

	var procs sendQueueProcs
	for name, target := range map[string]*uintptr{
		"pcap_sendqueue_alloc":    &procs.alloc,
		"pcap_sendqueue_queue":    &procs.queue,
		"pcap_sendqueue_transmit": &procs.transmit,
		"pcap_sendqueue_destroy":  &procs.destroy,
	} {
		if *target, err = windows.GetProcAddress(module, name); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	return &procs, nil
}

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
	procs  *sendQueueProcs
	handle *pcap.Handle
	// pcapT is zero once the sender is closed: the handle is about to be
	// freed and must not be touched again.
	pcapT uintptr
	// header lives on the heap so that its address stays put for the
	// duration of a call.
	header *sendQueueHeader
}

func newPcapFrameSender(handle *pcap.Handle) (frameSender, error) {
	procs, err := loadSendQueueProcs()
	if err != nil {
		return nil, err
	}

	// The queue is transmitted on the capture handle itself, and gopacket
	// keeps the underlying pcap_t in an unexported field. Reading it is the
	// alternative to opening the adapter a second time just to send.
	field := reflect.ValueOf(handle).Elem().FieldByName("cptr")
	if !field.IsValid() || field.Kind() != reflect.Uintptr || field.Uint() == 0 {
		return nil, errors.New("gopacket no longer exposes the pcap handle the way this expects")
	}

	return &queueSender{
		procs:  procs,
		handle: handle,
		pcapT:  uintptr(field.Uint()),
		header: new(sendQueueHeader),
	}, nil
}

func (s *queueSender) send(frames [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// The outbound loop can outlive Close by a batch, and by then pcap_t is
	// freed memory.
	if s.pcapT == 0 {
		return io.ErrClosedPipe
	}

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

	queue, _, _ := syscall.SyscallN(s.procs.alloc, size)
	if queue == 0 {
		return errors.New("pcap_sendqueue_alloc failed")
	}
	defer syscall.SyscallN(s.procs.destroy, queue)

	for _, frame := range frames {
		if len(frame) == 0 {
			continue
		}
		*s.header = sendQueueHeader{caplen: uint32(len(frame)), length: uint32(len(frame))}
		ret, _, _ := syscall.SyscallN(s.procs.queue,
			queue, uintptr(unsafe.Pointer(s.header)), uintptr(unsafe.Pointer(&frame[0])))
		if int32(ret) != 0 {
			return errors.New("pcap_sendqueue_queue failed")
		}
	}
	runtime.KeepAlive(frames)

	// sync = 0: send as fast as possible, ignoring the timestamps.
	ret, _, _ := syscall.SyscallN(s.procs.transmit, s.pcapT, queue, 0)
	// The function returns a 32 bit count; the rest of the register is noise.
	sent := uintptr(uint32(ret))
	if sent < size {
		return fmt.Errorf("pcap_sendqueue_transmit sent %d of %d bytes: %w", sent, size, s.handle.Error())
	}
	return nil
}

// close detaches the sender from the handle. It waits for a transmit in
// flight, so the caller is free to close the handle as soon as it returns.
func (s *queueSender) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pcapT = 0
	return nil
}
