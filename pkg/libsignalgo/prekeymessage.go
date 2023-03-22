package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import "runtime"

type PreKeyMessage struct {
	ptr *C.SignalPreKeySignalMessage
}

func wrapPreKeyMessage(ptr *C.SignalPreKeySignalMessage) *PreKeyMessage {
	preKeyMessage := &PreKeyMessage{ptr: ptr}
	runtime.SetFinalizer(preKeyMessage, (*PreKeyMessage).Destroy)
	return preKeyMessage
}

func DeserializePreKeyMessage(serialized []byte) (*PreKeyMessage, error) {
	var m *C.SignalPreKeySignalMessage
	signalFfiError := C.signal_pre_key_signal_message_deserialize(&m, BytesToBuffer(serialized))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPreKeyMessage(m), nil
}

func (m *PreKeyMessage) Clone() (*PreKeyMessage, error) {
	var cloned *C.SignalPreKeySignalMessage
	signalFfiError := C.signal_pre_key_signal_message_clone(&cloned, m.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPreKeyMessage(cloned), nil
}

func (m *PreKeyMessage) Destroy() error {
	runtime.SetFinalizer(m, nil)
	return wrapError(C.signal_pre_key_signal_message_destroy(m.ptr))
}

func (m *PreKeyMessage) Serialize() ([]byte, error) {
	var serialized *C.uchar
	var length C.ulong
	signalFfiError := C.signal_pre_key_signal_message_serialize(&serialized, &length, m.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(serialized, length), nil
}

func (m *PreKeyMessage) GetVersion() (uint32, error) {
	var version C.uint
	signalFfiError := C.signal_pre_key_signal_message_get_version(&version, m.ptr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return uint32(version), nil
}

func (m *PreKeyMessage) GetRegistrationID() (uint32, error) {
	var registrationID C.uint
	signalFfiError := C.signal_pre_key_signal_message_get_registration_id(&registrationID, m.ptr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return uint32(registrationID), nil
}

func (m *PreKeyMessage) GetPreKeyID() (*uint32, error) {
	var preKeyID C.uint
	signalFfiError := C.signal_pre_key_signal_message_get_pre_key_id(&preKeyID, m.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	if preKeyID == C.uint(0xffffffff) {
		return nil, nil
	}
	return (*uint32)(&preKeyID), nil
}

func (m *PreKeyMessage) GetSignedPreKeyID() (uint32, error) {
	var signedPreKeyID C.uint
	signalFfiError := C.signal_pre_key_signal_message_get_signed_pre_key_id(&signedPreKeyID, m.ptr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return uint32(signedPreKeyID), nil
}

func (m *PreKeyMessage) GetBaseKey() (*PublicKey, error) {
	var publicKey *C.SignalPublicKey
	signalFfiError := C.signal_pre_key_signal_message_get_base_key(&publicKey, m.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPublicKey(publicKey), nil
}

func (m *PreKeyMessage) GetIdentityKey() (*IdentityKey, error) {
	var publicKey *C.SignalPublicKey
	signalFfiError := C.signal_pre_key_signal_message_get_identity_key(&publicKey, m.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return &IdentityKey{wrapPublicKey(publicKey)}, nil
}

func (m *PreKeyMessage) GetSignalMessage() (*Message, error) {
	var message *C.SignalMessage
	signalFfiError := C.signal_pre_key_signal_message_get_signal_message(&message, m.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapMessage(message), nil
}
