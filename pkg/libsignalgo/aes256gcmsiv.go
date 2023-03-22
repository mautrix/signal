package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import "runtime"

type AES256_GCM_SIV struct {
	ptr *C.SignalAes256GcmSiv
}

func wrapAES256_GCM_SIV(ptr *C.SignalAes256GcmSiv) *AES256_GCM_SIV {
	aes := &AES256_GCM_SIV{ptr: ptr}
	runtime.SetFinalizer(aes, (*AES256_GCM_SIV).Destroy)
	return aes
}

func NewAES256_GCM_SIV(key []byte) (*AES256_GCM_SIV, error) {
	var aes *C.SignalAes256GcmSiv
	signalFfiError := C.signal_aes256_gcm_siv_new(&aes, BytesToBuffer(key))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapAES256_GCM_SIV(aes), nil
}

func (aes *AES256_GCM_SIV) Destroy() error {
	runtime.SetFinalizer(aes, nil)
	return wrapError(C.signal_aes256_gcm_siv_destroy(aes.ptr))
}

func (aes *AES256_GCM_SIV) Encrypt(plaintext, nonce, associatedData []byte) ([]byte, error) {
	var encrypted *C.uchar
	var length C.ulong
	signalFfiError := C.signal_aes256_gcm_siv_encrypt(&encrypted, &length, aes.ptr, BytesToBuffer(plaintext), BytesToBuffer(nonce), BytesToBuffer(associatedData))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(encrypted, length), nil
}

func (aes *AES256_GCM_SIV) Decrypt(ciphertext, nonce, associatedData []byte) ([]byte, error) {
	var decrypted *C.uchar
	var length C.ulong
	signalFfiError := C.signal_aes256_gcm_siv_decrypt(&decrypted, &length, aes.ptr, BytesToBuffer(ciphertext), BytesToBuffer(nonce), BytesToBuffer(associatedData))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(decrypted, length), nil
}
