package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import "time"

func Encrypt(plaintext []byte, forAddress *Address, sessionStore SessionStore, identityKeyStore IdentityKeyStore, ctx *CallbackContext) (*CiphertextMessage, error) {
	var ciphertextMessage *C.SignalCiphertextMessage
	var now C.uint64_t = C.uint64_t(time.Now().Unix())
	signalFfiError := C.signal_encrypt_message(
		&ciphertextMessage,
		BytesToBuffer(plaintext),
		forAddress.ptr,
		wrapSessionStore(sessionStore),
		wrapIdentityKeyStore(identityKeyStore),
		now,
	)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapCiphertextMessage(ciphertextMessage), nil
}
