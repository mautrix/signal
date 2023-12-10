package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import (
	"runtime"
)

func Decrypt(message *Message, fromAddress *Address, sessionStore SessionStore, identityStore IdentityKeyStore, ctx *CallbackContext) ([]byte, error) {
	var decrypted C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_decrypt_message(
		&decrypted,
		message.ptr,
		fromAddress.ptr,
		wrapSessionStore(sessionStore),
		wrapIdentityKeyStore(identityStore),
	)
	if signalFfiError != nil {
		return nil, wrapCallbackError(signalFfiError, ctx)
	}
	return CopySignalOwnedBufferToBytes(decrypted), nil
}

type Message struct {
	ptr *C.SignalMessage
}

func wrapMessage(ptr *C.SignalMessage) *Message {
	message := &Message{ptr: ptr}
	runtime.SetFinalizer(message, (*Message).Destroy)
	return message
}

func DeserializeMessage(serialized []byte) (*Message, error) {
	var m *C.SignalMessage
	signalFfiError := C.signal_message_deserialize(&m, BytesToBuffer(serialized))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapMessage(m), nil
}

func (m *Message) Clone() (*Message, error) {
	var cloned *C.SignalMessage
	signalFfiError := C.signal_message_clone(&cloned, m.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapMessage(cloned), nil
}

func (m *Message) Destroy() error {
	runtime.SetFinalizer(m, nil)
	return wrapError(C.signal_message_destroy(m.ptr))
}

func (m *Message) GetBody() ([]byte, error) {
	var body C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_message_get_body(&body, m.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(body), nil
}

func (m *Message) Serialize() ([]byte, error) {
	var serialized C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_message_get_serialized(&serialized, m.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(serialized), nil
}

func (m *Message) GetMessageVersion() (uint32, error) {
	var messageVersion C.uint32_t
	signalFfiError := C.signal_message_get_message_version(&messageVersion, m.ptr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return uint32(messageVersion), nil
}

func (m *Message) GetCounter() (uint32, error) {
	var counter C.uint32_t
	signalFfiError := C.signal_message_get_counter(&counter, m.ptr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return uint32(counter), nil
}

func (m *Message) VerifyMAC(sender, receiver *PublicKey, macKey []byte) (bool, error) {
	var result C.bool
	signalFfiError := C.signal_message_verify_mac(&result, m.ptr, sender.ptr, receiver.ptr, BytesToBuffer(macKey))
	if signalFfiError != nil {
		return false, wrapError(signalFfiError)
	}
	return bool(result), nil
}
