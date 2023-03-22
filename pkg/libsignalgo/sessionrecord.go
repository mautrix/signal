package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"
import "runtime"

type SessionRecord struct {
	ptr *C.SignalSessionRecord
}

func wrapSessionRecord(ptr *C.SignalSessionRecord) *SessionRecord {
	sessionRecord := &SessionRecord{ptr: ptr}
	runtime.SetFinalizer(sessionRecord, (*SessionRecord).Destroy)
	return sessionRecord
}

func DeserializeSessionRecord(serialized []byte) (*SessionRecord, error) {
	var ptr *C.SignalSessionRecord
	signalFfiError := C.signal_session_record_deserialize(&ptr, BytesToBuffer(serialized))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapSessionRecord(ptr), nil
}

func (sr *SessionRecord) Clone() (*SessionRecord, error) {
	var clone *C.SignalSessionRecord
	signalFfiError := C.signal_session_record_clone(&clone, sr.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapSessionRecord(clone), nil
}

func (sr *SessionRecord) Destroy() error {
	runtime.SetFinalizer(sr, nil)
	return wrapError(C.signal_session_record_destroy(sr.ptr))
}

func (sr *SessionRecord) ArchiveCurrentState() error {
	return wrapError(C.signal_session_record_archive_current_state(sr.ptr))
}

func (sr *SessionRecord) CurrentRatchetKeyMatches(key *PublicKey) (bool, error) {
	var result C.bool
	signalFfiError := C.signal_session_record_current_ratchet_key_matches(&result, sr.ptr, key.ptr)
	if signalFfiError != nil {
		return false, wrapError(signalFfiError)
	}
	return bool(result), nil
}

func (sr *SessionRecord) HasCurrentState() (bool, error) {
	var result C.bool
	signalFfiError := C.signal_session_record_has_current_state(&result, sr.ptr)
	if signalFfiError != nil {
		return false, wrapError(signalFfiError)
	}
	return bool(result), nil
}

func (sr *SessionRecord) Serialize() ([]byte, error) {
	var serialized *C.uchar
	var length C.ulong
	signalFfiError := C.signal_session_record_serialize(&serialized, &length, sr.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(serialized, length), nil
}

func (sr *SessionRecord) GetLocalRegistrationID() (uint32, error) {
	var result C.uint32_t
	signalFfiError := C.signal_session_record_get_local_registration_id(&result, sr.ptr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return uint32(result), nil
}

func (sr *SessionRecord) GetRemoteRegistrationID() (uint32, error) {
	var result C.uint32_t
	signalFfiError := C.signal_session_record_get_remote_registration_id(&result, sr.ptr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return uint32(result), nil
}
