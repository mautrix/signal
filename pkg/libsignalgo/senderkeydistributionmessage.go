package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"
import (
	"runtime"
	"unsafe"

	"github.com/google/uuid"
	gopointer "github.com/mattn/go-pointer"
)

func ProcessSenderKeyDistributionMessage(message *SenderKeyDistributionMessage, fromSender *Address, store SenderKeyStore, ctx *CallbackContext) error {
	contextPointer := gopointer.Save(ctx)
	defer gopointer.Unref(contextPointer)

	signalFfiError := C.signal_process_sender_key_distribution_message(
		fromSender.ptr,
		message.ptr,
		wrapSenderKeyStore(store),
		contextPointer,
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
	contextPointer := gopointer.Save(ctx)
	defer gopointer.Unref(contextPointer)

	var skdm *C.SignalSenderKeyDistributionMessage
	signalFfiError := C.signal_sender_key_distribution_message_create(
		&skdm,
		sender.ptr,
		(*[C.SignalUUID_LEN]C.uchar)(unsafe.Pointer(&distributionID)),
		wrapSenderKeyStore(store),
		contextPointer)
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
	var serialized *C.uchar
	var length C.ulong
	signalFfiError := C.signal_sender_key_distribution_message_serialize(&serialized, &length, sc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(serialized, length), nil
}

func (sc *SenderKeyDistributionMessage) Process(sender *Address, store SenderKeyStore, ctx *CallbackContext) error {
	contextPointer := gopointer.Save(ctx)
	defer gopointer.Unref(contextPointer)

	signalFfiError := C.signal_process_sender_key_distribution_message(
		sender.ptr,
		sc.ptr,
		wrapSenderKeyStore(store),
		contextPointer)
	if signalFfiError != nil {
		return wrapCallbackError(signalFfiError, ctx)
	}
	return nil
}
