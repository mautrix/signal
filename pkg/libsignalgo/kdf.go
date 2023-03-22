package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import "unsafe"

func HKDFDerive(outputLength int, inputKeyMaterial, salt, info []byte) ([]byte, error) {
	output := BorrowedMutableBuffer(outputLength)
	signalFfiError := C.signal_hkdf_derive(output, BytesToBuffer(inputKeyMaterial), BytesToBuffer(info), BytesToBuffer(salt))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	// No need to wrap this in a CopyBufferToBytes since this is allocated by
	// Go and thus will be properly garbage collected.
	return C.GoBytes(unsafe.Pointer(output.base), C.int(output.length)), nil
}
