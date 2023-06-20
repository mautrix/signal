package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import "runtime"

type PlaintextContent struct {
	ptr *C.SignalPlaintextContent
}

func wrapPlaintextContent(ptr *C.SignalPlaintextContent) *PlaintextContent {
	plaintextContent := &PlaintextContent{ptr: ptr}
	runtime.SetFinalizer(plaintextContent, (*PlaintextContent).Destroy)
	return plaintextContent
}

func PlaintextContentFromDecryptionErrorMessage(message DecryptionErrorMessage) (*PlaintextContent, error) {
	var pc *C.SignalPlaintextContent
	signalFfiError := C.signal_plaintext_content_from_decryption_error_message(&pc, message.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPlaintextContent(pc), nil
}

func DeserializePlaintextContent(plaintextContentBytes []byte) (*PlaintextContent, error) {
	var pc *C.SignalPlaintextContent
	signalFfiError := C.signal_plaintext_content_deserialize(&pc, BytesToBuffer(plaintextContentBytes))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPlaintextContent(pc), nil
}

func (pk *PlaintextContent) Clone() (*PlaintextContent, error) {
	var cloned *C.SignalPlaintextContent
	signalFfiError := C.signal_plaintext_content_clone(&cloned, pk.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPlaintextContent(cloned), nil
}

func (p *PlaintextContent) Destroy() error {
	runtime.SetFinalizer(p, nil)
	return wrapError(C.signal_plaintext_content_destroy(p.ptr))
}

func (pc *PlaintextContent) Serialize() ([]byte, error) {
	var serialized C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_plaintext_content_serialize(&serialized, pc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(serialized), nil
}

func (pc *PlaintextContent) GetBody() ([]byte, error) {
	var body C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_plaintext_content_get_body(&body, pc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(body), nil
}
