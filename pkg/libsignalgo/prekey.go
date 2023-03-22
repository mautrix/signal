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

func DecryptPreKey(preKeyMessage *PreKeyMessage, fromAddress *Address, sessionStore SessionStore, identityStore IdentityKeyStore, preKeyStore PreKeyStore, signedPreKeyStore SignedPreKeyStore, ctx *CallbackContext) ([]byte, error) {
	contextPointer := gopointer.Save(ctx)
	defer gopointer.Unref(contextPointer)

	var decrypted *C.uchar
	var length C.ulong
	signalFfiError := C.signal_decrypt_pre_key_message(
		&decrypted,
		&length,
		preKeyMessage.ptr,
		fromAddress.ptr,
		wrapSessionStore(sessionStore),
		wrapIdentityKeyStore(identityStore),
		wrapPreKeyStore(preKeyStore),
		wrapSignedPreKeyStore(signedPreKeyStore),
		contextPointer,
	)
	if signalFfiError != nil {
		return nil, wrapCallbackError(signalFfiError, ctx)
	}
	return CopyBufferToBytes(decrypted, length), nil
}

type PreKeyRecord struct {
	ptr *C.SignalPreKeyRecord
}

func wrapPreKeyRecord(ptr *C.SignalPreKeyRecord) *PreKeyRecord {
	pkr := &PreKeyRecord{ptr: ptr}
	runtime.SetFinalizer(pkr, (*PreKeyRecord).Destroy)
	return pkr
}

func NewPreKeyRecord(id uint32, publicKey *PublicKey, privateKey *PrivateKey) (*PreKeyRecord, error) {
	var pkr *C.SignalPreKeyRecord
	signalFfiError := C.signal_pre_key_record_new(&pkr, C.uint32_t(id), publicKey.ptr, privateKey.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPreKeyRecord(pkr), nil
}

func NewPreKeyRecordFromPrivateKey(id uint32, privateKey *PrivateKey) (*PreKeyRecord, error) {
	pub, err := privateKey.GetPublicKey()
	if err != nil {
		return nil, err
	}
	return NewPreKeyRecord(id, pub, privateKey)
}

func DeserializePreKeyRecord(serialized []byte) (*PreKeyRecord, error) {
	var pkr *C.SignalPreKeyRecord
	signalFfiError := C.signal_pre_key_record_deserialize(&pkr, BytesToBuffer(serialized))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPreKeyRecord(pkr), nil
}

func (pkr *PreKeyRecord) Clone() (*PreKeyRecord, error) {
	var cloned *C.SignalPreKeyRecord
	signalFfiError := C.signal_pre_key_record_clone(&cloned, pkr.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPreKeyRecord(cloned), nil
}

func (pkr *PreKeyRecord) Destroy() error {
	runtime.SetFinalizer(pkr, nil)
	return wrapError(C.signal_pre_key_record_destroy(pkr.ptr))
}

func (pkr *PreKeyRecord) Serialize() ([]byte, error) {
	var serialized *C.uchar
	var length C.ulong
	signalFfiError := C.signal_pre_key_record_serialize(&serialized, &length, pkr.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(serialized, length), nil
}

func (pkr *PreKeyRecord) GetID() (int, error) {
	var id C.uint32_t
	signalFfiError := C.signal_pre_key_record_get_id(&id, pkr.ptr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return int(id), nil
}

func (pkr *PreKeyRecord) GetPublicKey() (*PublicKey, error) {
	var pub *C.SignalPublicKey
	signalFfiError := C.signal_pre_key_record_get_public_key(&pub, pkr.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPublicKey(pub), nil
}

func (pkr *PreKeyRecord) GetPrivateKey() (*PrivateKey, error) {
	var priv *C.SignalPrivateKey
	signalFfiError := C.signal_pre_key_record_get_private_key(&priv, pkr.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPrivateKey(priv), nil
}
