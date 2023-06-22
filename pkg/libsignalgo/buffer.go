package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import (
	"unsafe"
)

func BorrowedMutableBuffer(length int) C.SignalBorrowedMutableBuffer {
	data := make([]byte, length)
	return C.SignalBorrowedMutableBuffer{
		base:   (*C.uchar)(unsafe.Pointer(&data[0])),
		length: C.uintptr_t(len(data)),
	}
}

func BytesToBuffer(data []byte) C.SignalBorrowedBuffer {
	buf := C.SignalBorrowedBuffer{
		length: C.uintptr_t(len(data)),
	}
	if len(data) > 0 {
		buf.base = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	return buf
}

func EmptyBorrowedBuffer() C.SignalBorrowedBuffer {
	return C.SignalBorrowedBuffer{}
}

// TODO: Try out this code from ChatGPT that might be more memory safe
// - Makes copy of data
// - Sets finalizer to free memory
//
//type CBytesWrapper struct {
//	c unsafe.Pointer
//}
//
//func CBytes(b []byte) *CBytesWrapper {
//	if len(b) == 0 {
//		return &CBytesWrapper{nil}
//	}
//	c := C.malloc(C.size_t(len(b)))
//	copy((*[1 << 30]byte)(c)[:], b)
//	return &CBytesWrapper{c}
//}
//
//func BytesToBuffer(data []byte) C.SignalBorrowedBuffer {
//	cData := CBytes(data)
//	buf := C.SignalBorrowedBuffer{
//		length: C.uintptr_t(len(data)),
//	}
//	if len(data) > 0 {
//		buf.base = (*C.uchar)(cData.c)
//	}
//
//	// Setting finalizer here
//	runtime.SetFinalizer(cData, func(c *CBytesWrapper) { C.free(c.c) })
//
//	return buf
//}
//
