package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"
import (
	"runtime"
)

type SenderKeyRecord struct {
	ptr *C.SignalSenderKeyRecord
}

func wrapSenderKeyRecord(ptr *C.SignalSenderKeyRecord) *SenderKeyRecord {
	sc := &SenderKeyRecord{ptr: ptr}
	runtime.SetFinalizer(sc, (*SenderKeyRecord).Destroy)
	return sc
}

func DeserializeSenderKeyRecord(serialized []byte) (*SenderKeyRecord, error) {
	var sc *C.SignalSenderKeyRecord
	signalFfiError := C.signal_sender_key_record_deserialize(&sc, BytesToBuffer(serialized))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapSenderKeyRecord(sc), nil
}

func (skr *SenderKeyRecord) Serialize() ([]byte, error) {
	var serialized *C.uchar
	var length C.ulong
	signalFfiError := C.signal_sender_key_record_serialize(&serialized, &length, skr.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(serialized, length), nil
}

func (skr *SenderKeyRecord) Clone() (*SenderKeyRecord, error) {
	var cloned *C.SignalSenderKeyRecord
	signalFfiError := C.signal_sender_key_record_clone(&cloned, skr.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapSenderKeyRecord(cloned), nil
}

func (skr *SenderKeyRecord) Destroy() error {
	runtime.SetFinalizer(skr, nil)
	return wrapError(C.signal_sender_key_record_destroy(skr.ptr))
}
