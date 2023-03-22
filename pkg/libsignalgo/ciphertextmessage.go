package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import "runtime"

type CiphertextMessageType uint8

const (
	CiphertextMessageTypeWhisper   CiphertextMessageType = 2
	CiphertextMessageTypePreKey    CiphertextMessageType = 3
	CiphertextMessageTypeSenderKey CiphertextMessageType = 7
	CiphertextMessageTypePlaintext CiphertextMessageType = 8
)

type CiphertextMessage struct {
	ptr *C.SignalCiphertextMessage
}

func wrapCiphertextMessage(ptr *C.SignalCiphertextMessage) *CiphertextMessage {
	ciphertextMessage := &CiphertextMessage{ptr: ptr}
	runtime.SetFinalizer(ciphertextMessage, (*CiphertextMessage).Destroy)
	return ciphertextMessage
}

func NewCiphertextMessage(plaintext PlaintextContent) (*CiphertextMessage, error) {
	var ciphertextMessage *C.SignalCiphertextMessage
	signalFfiError := C.signal_ciphertext_message_from_plaintext_content(&ciphertextMessage, plaintext.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapCiphertextMessage(ciphertextMessage), nil
}

func (c *CiphertextMessage) Destroy() error {
	runtime.SetFinalizer(c, nil)
	return wrapError(C.signal_ciphertext_message_destroy(c.ptr))
}

func (c *CiphertextMessage) Serialize() ([]byte, error) {
	var serialized *C.uchar
	var length C.ulong
	signalFfiError := C.signal_ciphertext_message_serialize(&serialized, &length, c.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(serialized, length), nil
}

func (c *CiphertextMessage) MessageType() (CiphertextMessageType, error) {
	var messageType C.uint8_t
	signalFfiError := C.signal_ciphertext_message_type(&messageType, c.ptr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return CiphertextMessageType(messageType), nil
}
