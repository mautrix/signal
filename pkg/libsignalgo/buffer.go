package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
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
