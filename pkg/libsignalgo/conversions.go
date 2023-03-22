package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
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
