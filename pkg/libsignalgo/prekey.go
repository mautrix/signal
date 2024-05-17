// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Sumner Evans
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl -lm
#include "./libsignal-ffi.h"
*/
import "C"
import (
	"context"
	"runtime"
)

func DecryptPreKey(ctx context.Context, preKeyMessage *PreKeyMessage, fromAddress *Address, sessionStore SessionStore, identityStore IdentityKeyStore, preKeyStore PreKeyStore, signedPreKeyStore SignedPreKeyStore, kyberPreKeyStore KyberPreKeyStore) ([]byte, error) {
	callbackCtx := NewCallbackContext(ctx)
	defer callbackCtx.Unref()
	var decrypted C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_decrypt_pre_key_message(
		&decrypted,
		preKeyMessage.ptr,
		fromAddress.ptr,
		callbackCtx.wrapSessionStore(sessionStore),
		callbackCtx.wrapIdentityKeyStore(identityStore),
		callbackCtx.wrapPreKeyStore(preKeyStore),
		callbackCtx.wrapSignedPreKeyStore(signedPreKeyStore),
		callbackCtx.wrapKyberPreKeyStore(kyberPreKeyStore),
	)
	runtime.KeepAlive(preKeyMessage)
	runtime.KeepAlive(fromAddress)
	if signalFfiError != nil {
		return nil, callbackCtx.wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(decrypted), nil
}

type PreKeyRecord struct {
	nc  noCopy
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
	runtime.KeepAlive(publicKey)
	runtime.KeepAlive(privateKey)
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
	runtime.KeepAlive(serialized)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPreKeyRecord(pkr), nil
}

func (pkr *PreKeyRecord) Clone() (*PreKeyRecord, error) {
	var cloned *C.SignalPreKeyRecord
	signalFfiError := C.signal_pre_key_record_clone(&cloned, pkr.ptr)
	runtime.KeepAlive(pkr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPreKeyRecord(cloned), nil
}

func (pkr *PreKeyRecord) Destroy() error {
	pkr.CancelFinalizer()
	return wrapError(C.signal_pre_key_record_destroy(pkr.ptr))
}

func (pkr *PreKeyRecord) CancelFinalizer() {
	runtime.SetFinalizer(pkr, nil)
}

func (pkr *PreKeyRecord) Serialize() ([]byte, error) {
	var serialized C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_pre_key_record_serialize(&serialized, pkr.ptr)
	runtime.KeepAlive(pkr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(serialized), nil
}

func (pkr *PreKeyRecord) GetID() (uint32, error) {
	var id C.uint32_t
	signalFfiError := C.signal_pre_key_record_get_id(&id, pkr.ptr)
	runtime.KeepAlive(pkr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return uint32(id), nil
}

func (pkr *PreKeyRecord) GetPublicKey() (*PublicKey, error) {
	var pub *C.SignalPublicKey
	signalFfiError := C.signal_pre_key_record_get_public_key(&pub, pkr.ptr)
	runtime.KeepAlive(pkr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPublicKey(pub), nil
}

func (pkr *PreKeyRecord) GetPrivateKey() (*PrivateKey, error) {
	var priv *C.SignalPrivateKey
	signalFfiError := C.signal_pre_key_record_get_private_key(&priv, pkr.ptr)
	runtime.KeepAlive(pkr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPrivateKey(priv), nil
}
