package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import (
	"runtime"
	"time"
)

type KyberPreKeyRecord struct {
	ptr *C.SignalKyberPreKeyRecord
}

type KyberKeyPair struct {
	ptr *C.SignalKyberKeyPair
}

func wrapKyberPreKeyRecord(ptr *C.SignalKyberPreKeyRecord) *KyberPreKeyRecord {
	spkr := &KyberPreKeyRecord{ptr: ptr}
	runtime.SetFinalizer(spkr, (*KyberPreKeyRecord).Destroy)
	return spkr
}

func NewKyberPreKeyRecord(id uint32, timestamp time.Time, keyPair *KyberKeyPair, signature []byte) (*KyberPreKeyRecord, error) {
	var spkr *C.SignalKyberPreKeyRecord
	signalFfiError := C.signal_kyber_pre_key_record_new(&spkr, C.uint32_t(id), C.uint64_t(timestamp.UnixMilli()), keyPair.ptr, BytesToBuffer(signature))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapKyberPreKeyRecord(spkr), nil
}

func DeserializeKyberPreKeyRecord(serialized []byte) (*KyberPreKeyRecord, error) {
	var spkr *C.SignalKyberPreKeyRecord
	signalFfiError := C.signal_kyber_pre_key_record_deserialize(&spkr, BytesToBuffer(serialized))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapKyberPreKeyRecord(spkr), nil
}

func (spkr *KyberPreKeyRecord) Clone() (*KyberPreKeyRecord, error) {
	var cloned *C.SignalKyberPreKeyRecord
	signalFfiError := C.signal_kyber_pre_key_record_clone(&cloned, spkr.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapKyberPreKeyRecord(cloned), nil
}

func (spkr *KyberPreKeyRecord) Destroy() error {
	//runtime.SetFinalizer(spkr, nil)
	return nil //wrapError(C.signal_kyber_pre_key_record_destroy(spkr.ptr))
}

func (spkr *KyberPreKeyRecord) Serialize() ([]byte, error) {
	var serialized C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_kyber_pre_key_record_serialize(&serialized, spkr.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(serialized), nil
}

func (spkr *KyberPreKeyRecord) GetSignature() ([]byte, error) {
	var signature C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_kyber_pre_key_record_get_signature(&signature, spkr.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(signature), nil
}

func (spkr *KyberPreKeyRecord) GetID() (uint, error) {
	var id C.uint32_t
	signalFfiError := C.signal_kyber_pre_key_record_get_id(&id, spkr.ptr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return uint(id), nil
}

func (spkr *KyberPreKeyRecord) GetTimestamp() (time.Time, error) {
	var ts C.uint64_t
	signalFfiError := C.signal_kyber_pre_key_record_get_timestamp(&ts, spkr.ptr)
	if signalFfiError != nil {
		return time.Time{}, wrapError(signalFfiError)
	}
	return time.UnixMilli(int64(ts)), nil
}

func (spkr *KyberPreKeyRecord) GetPublicKey() (*PublicKey, error) {
	var pub *C.SignalPublicKey
	signalFfiError := C.signal_kyber_pre_key_record_get_public_key(&pub, spkr.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPublicKey(pub), nil
}
