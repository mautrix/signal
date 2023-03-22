package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import (
	"unsafe"

	"github.com/google/uuid"
	gopointer "github.com/mattn/go-pointer"
)

var UUIDLen = sizeMustMatch(C.SignalUUID_LEN, 16)

func GroupEncrypt(ptext []byte, sender *Address, distributionID uuid.UUID, store SenderKeyStore, ctx *CallbackContext) (*CiphertextMessage, error) {
	contextPointer := gopointer.Save(ctx)
	defer gopointer.Unref(contextPointer)

	var ciphertextMessage *C.SignalCiphertextMessage
	signalFfiError := C.signal_group_encrypt_message(
		&ciphertextMessage,
		sender.ptr,
		(*[C.SignalUUID_LEN]C.uchar)(unsafe.Pointer(&distributionID)),
		BytesToBuffer(ptext),
		wrapSenderKeyStore(store),
		contextPointer)
	if signalFfiError != nil {
		return nil, wrapCallbackError(signalFfiError, ctx)
	}
	return wrapCiphertextMessage(ciphertextMessage), nil
}

func GroupDecrypt(ctext []byte, sender *Address, store SenderKeyStore, ctx *CallbackContext) ([]byte, error) {
	contextPointer := gopointer.Save(ctx)
	defer gopointer.Unref(contextPointer)

	var resp *C.uchar
	var length C.ulong
	signalFfiError := C.signal_group_decrypt_message(
		&resp,
		&length,
		sender.ptr,
		BytesToBuffer(ctext),
		wrapSenderKeyStore(store),
		contextPointer)
	if signalFfiError != nil {
		return nil, wrapCallbackError(signalFfiError, ctx)
	}
	return CopyBufferToBytes(resp, length), nil
}
