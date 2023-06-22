package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import (
	"runtime"

	gopointer "github.com/mattn/go-pointer"
)

func ProcessPreKeyBundle(bundle *PreKeyBundle, forAddress *Address, sessionStore SessionStore, identityStore IdentityKeyStore, ctx *CallbackContext) error {
	contextPointer := gopointer.Save(ctx)
	defer gopointer.Unref(contextPointer)

	signalFfiError := C.signal_process_prekey_bundle(
		bundle.ptr,
		forAddress.ptr,
		wrapSessionStore(sessionStore),
		wrapIdentityKeyStore(identityStore),
		contextPointer,
	)
	return wrapCallbackError(signalFfiError, ctx)
}

type PreKeyBundle struct {
	ptr *C.SignalPreKeyBundle
}

func wrapPreKeyBundle(ptr *C.SignalPreKeyBundle) *PreKeyBundle {
	bundle := &PreKeyBundle{ptr: ptr}
	runtime.SetFinalizer(bundle, (*PreKeyBundle).Destroy)
	return bundle
}

func NewPreKeyBundleWithoutPrekey(registrationID uint32, deviceID uint32, signedPreKeyID uint32, signedPreKey *PublicKey, signedPreKeySignature []byte, identityKey *IdentityKey) (*PreKeyBundle, error) {
	var pkb *C.SignalPreKeyBundle
	var zero uint32 = 0
	var kyberSignatureBuffer = EmptyBorrowedBuffer()
	signalFfiError := C.signal_pre_key_bundle_new(
		&pkb,
		C.uint32_t(registrationID),
		C.uint32_t(deviceID),
		C.uint32_t(^zero), // Turns out we need to pass in a max uint32 value to indicate no prekey
		nil,
		C.uint32_t(signedPreKeyID),
		signedPreKey.ptr,
		BytesToBuffer(signedPreKeySignature),
		identityKey.publicKey.ptr,
		C.uint32_t(^zero), // No kyber prekey either
		nil,
		kyberSignatureBuffer,
	)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPreKeyBundle(pkb), nil
}

func NewPreKeyBundle(registrationID uint32, deviceID uint32, preKeyID uint32, preKey *PublicKey, signedPreKeyID uint32, signedPreKey *PublicKey, signedPreKeySignature []byte, identityKey *IdentityKey) (*PreKeyBundle, error) {
	var pkb *C.SignalPreKeyBundle
	var zero uint32 = 0
	var kyberSignatureBuffer = EmptyBorrowedBuffer()
	signalFfiError := C.signal_pre_key_bundle_new(
		&pkb,
		C.uint32_t(registrationID),
		C.uint32_t(deviceID),
		C.uint32_t(preKeyID),
		preKey.ptr,
		C.uint32_t(signedPreKeyID),
		signedPreKey.ptr,
		BytesToBuffer(signedPreKeySignature),
		identityKey.publicKey.ptr,
		C.uint32_t(^zero), // No kyber prekey
		nil,
		kyberSignatureBuffer,
	)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPreKeyBundle(pkb), nil
}

func (pkb *PreKeyBundle) Clone() (*PreKeyBundle, error) {
	var cloned *C.SignalPreKeyBundle
	signalFfiError := C.signal_pre_key_bundle_clone(&cloned, pkb.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPreKeyBundle(cloned), nil
}

func (pkb *PreKeyBundle) Destroy() error {
	runtime.SetFinalizer(pkb, nil)
	return wrapError(C.signal_pre_key_bundle_destroy(pkb.ptr))
}

func (pkb *PreKeyBundle) GetIdentityKey() (*IdentityKey, error) {
	var pk *C.SignalPublicKey
	signalFfiError := C.signal_pre_key_bundle_get_identity_key(&pk, pkb.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return NewIdentityKeyFromPublicKey(wrapPublicKey(pk))
}
