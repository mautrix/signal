package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import (
	gopointer "github.com/mattn/go-pointer"
)

func Encrypt(plaintext []byte, forAddress *Address, sessionStore SessionStore, identityKeyStore IdentityKeyStore, ctx *CallbackContext) (*CiphertextMessage, error) {
	contextPtr := gopointer.Save(ctx)
	defer gopointer.Unref(contextPtr)

	var ciphertextMessage *C.SignalCiphertextMessage
	signalFfiError := C.signal_encrypt_message(
		&ciphertextMessage,
		BytesToBuffer(plaintext),
		forAddress.ptr,
		wrapSessionStore(sessionStore),
		wrapIdentityKeyStore(identityKeyStore),
		contextPtr,
	)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapCiphertextMessage(ciphertextMessage), nil
}
