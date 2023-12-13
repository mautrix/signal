package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import (
	"runtime"
	"time"
)

func ProcessPreKeyBundle(bundle *PreKeyBundle, forAddress *Address, sessionStore SessionStore, identityStore IdentityKeyStore, ctx *CallbackContext) error {
	var now C.uint64_t = C.uint64_t(time.Now().Unix())
	signalFfiError := C.signal_process_prekey_bundle(
		bundle.ptr,
		forAddress.ptr,
		wrapSessionStore(sessionStore),
		wrapIdentityKeyStore(identityStore),
		now,
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

func NewPreKeyBundle(
	registrationID uint32,
	deviceID uint32,
	preKeyID uint32,
	preKey *PublicKey,
	signedPreKeyID uint32,
	signedPreKey *PublicKey,
	signedPreKeySignature []byte,
	kyberPreKeyID uint32,
	kyberPreKey *KyberPublicKey,
	kyberPreKeySignature []byte,
	identityKey *IdentityKey,
) (*PreKeyBundle, error) {
	var pkb *C.SignalPreKeyBundle
	var zero uint32 = 0
	var kyberSignatureBuffer = EmptyBorrowedBuffer()
	if preKey == nil {
		preKey = &PublicKey{ptr: nil}
		preKeyID = ^zero
	}
	if kyberPreKey == nil {
		kyberPreKey = &KyberPublicKey{ptr: nil}
		kyberPreKeyID = ^zero
	} else {
		kyberSignatureBuffer = BytesToBuffer(kyberPreKeySignature)
	}
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
		C.uint32_t(kyberPreKeyID),
		kyberPreKey.ptr,
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
