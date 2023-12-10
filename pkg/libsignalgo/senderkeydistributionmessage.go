package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import (
	"runtime"
	"unsafe"

	"github.com/google/uuid"
)

func ProcessSenderKeyDistributionMessage(message *SenderKeyDistributionMessage, fromSender *Address, store SenderKeyStore, ctx *CallbackContext) error {
	signalFfiError := C.signal_process_sender_key_distribution_message(
		fromSender.ptr,
		message.ptr,
		wrapSenderKeyStore(store),
	)
	return wrapCallbackError(signalFfiError, ctx)
}

type SenderKeyDistributionMessage struct {
	ptr *C.SignalSenderKeyDistributionMessage
}

func wrapSenderKeyDistributionMessage(ptr *C.SignalSenderKeyDistributionMessage) *SenderKeyDistributionMessage {
	sc := &SenderKeyDistributionMessage{ptr: ptr}
	runtime.SetFinalizer(sc, (*SenderKeyDistributionMessage).Destroy)
	return sc
}

func NewSenderKeyDistributionMessage(sender *Address, distributionID uuid.UUID, store SenderKeyStore, ctx *CallbackContext) (*SenderKeyDistributionMessage, error) {
	var skdm *C.SignalSenderKeyDistributionMessage
	signalFfiError := C.signal_sender_key_distribution_message_create(
		&skdm,
		sender.ptr,
		(*[C.SignalUUID_LEN]C.uchar)(unsafe.Pointer(&distributionID)),
		wrapSenderKeyStore(store),
	)
	if signalFfiError != nil {
		return nil, wrapCallbackError(signalFfiError, ctx)
	}
	return wrapSenderKeyDistributionMessage(skdm), nil
}

func DeserializeSenderKeyDistributionMessage(serialized []byte) (*SenderKeyDistributionMessage, error) {
	var skdm *C.SignalSenderKeyDistributionMessage
	signalFfiError := C.signal_sender_key_distribution_message_deserialize(&skdm, BytesToBuffer(serialized))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapSenderKeyDistributionMessage(skdm), nil
}

func (sc *SenderKeyDistributionMessage) Destroy() error {
	runtime.SetFinalizer(sc, nil)
	return wrapError(C.signal_sender_key_distribution_message_destroy(sc.ptr))
}

func (sc *SenderKeyDistributionMessage) Serialize() ([]byte, error) {
	var serialized C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_sender_key_distribution_message_serialize(&serialized, sc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(serialized), nil
}

func (sc *SenderKeyDistributionMessage) Process(sender *Address, store SenderKeyStore, ctx *CallbackContext) error {
	signalFfiError := C.signal_process_sender_key_distribution_message(
		sender.ptr,
		sc.ptr,
		wrapSenderKeyStore(store),
	)
	if signalFfiError != nil {
		return wrapCallbackError(signalFfiError, ctx)
	}
	return nil
}
