package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import "unsafe"

func CopyCStringToString(cString *C.char) (s string) {
	s = C.GoString(cString)
	C.signal_free_string(cString)
	return
}

func CopyBufferToBytes(buffer *C.uchar, length C.size_t) (b []byte) {
	b = C.GoBytes(unsafe.Pointer(buffer), C.int(length))
	C.signal_free_buffer(buffer, length)
	return
}

func CopySignalOwnedBufferToBytes(buffer C.SignalOwnedBuffer) (b []byte) {
	b = C.GoBytes(unsafe.Pointer(buffer.base), C.int(buffer.length))
	C.signal_free_buffer(buffer.base, buffer.length)
	return
}
