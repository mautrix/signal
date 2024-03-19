// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Scott Weber
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
	"runtime"
	"time"
)

type KyberPreKeyRecord struct {
	nc  noCopy
	ptr *C.SignalKyberPreKeyRecord
}

type KyberKeyPair struct {
	nc  noCopy
	ptr *C.SignalKyberKeyPair
}

type KyberPublicKey struct {
	nc  noCopy
	ptr *C.SignalKyberPublicKey
}

type KyberSecretKey struct {
	nc  noCopy
	ptr *C.SignalKyberSecretKey
}

func wrapKyberKeyPair(ptr *C.SignalKyberKeyPair) *KyberKeyPair {
	kp := &KyberKeyPair{ptr: ptr}
	runtime.SetFinalizer(kp, (*KyberKeyPair).Destroy)
	return kp
}

func (kp *KyberKeyPair) Destroy() error {
	kp.CancelFinalizer()
	return wrapError(C.signal_kyber_key_pair_destroy(kp.ptr))
}

func (kp *KyberKeyPair) CancelFinalizer() {
	runtime.SetFinalizer(kp, nil)
}

func wrapKyberPublicKey(ptr *C.SignalKyberPublicKey) *KyberPublicKey {
	publicKey := &KyberPublicKey{ptr: ptr}
	runtime.SetFinalizer(publicKey, (*KyberPublicKey).Destroy)
	return publicKey
}

func (k *KyberPublicKey) Destroy() error {
	k.CancelFinalizer()
	return wrapError(C.signal_publickey_destroy(k.ptr))
}

func (k *KyberPublicKey) CancelFinalizer() {
	runtime.SetFinalizer(k, nil)
}

func wrapKyberSecretKey(ptr *C.SignalKyberSecretKey) *KyberSecretKey {
	secretKey := &KyberSecretKey{ptr: ptr}
	runtime.SetFinalizer(secretKey, (*KyberSecretKey).Destroy)
	return secretKey
}

func (k *KyberSecretKey) Destroy() error {
	k.CancelFinalizer()
	return wrapError(C.signal_kyber_secret_key_destroy(k.ptr))
}

func (k *KyberSecretKey) CancelFinalizer() {
	runtime.SetFinalizer(k, nil)
}

func wrapKyberPreKeyRecord(ptr *C.SignalKyberPreKeyRecord) *KyberPreKeyRecord {
	kpkr := &KyberPreKeyRecord{ptr: ptr}
	runtime.SetFinalizer(kpkr, (*KyberPreKeyRecord).Destroy)
	return kpkr
}

func (kp *KyberKeyPair) GetPublicKey() (*KyberPublicKey, error) {
	var pub *C.SignalKyberPublicKey
	signalFfiError := C.signal_kyber_key_pair_get_public_key(&pub, kp.ptr)
	runtime.KeepAlive(kp)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapKyberPublicKey(pub), nil
}

func (kp *KyberPublicKey) Serialize() ([]byte, error) {
	var serialized C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_kyber_public_key_serialize(&serialized, kp.ptr)
	runtime.KeepAlive(kp)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(serialized), nil
}

func DeserializeKyberPublicKey(serialized []byte) (*KyberPublicKey, error) {
	var kyberPublicKey *C.SignalKyberPublicKey
	signalFfiError := C.signal_kyber_public_key_deserialize(&kyberPublicKey, BytesToBuffer(serialized))
	runtime.KeepAlive(serialized)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapKyberPublicKey(kyberPublicKey), nil
}

func NewKyberPreKeyRecord(id uint32, timestamp time.Time, keyPair *KyberKeyPair, signature []byte) (*KyberPreKeyRecord, error) {
	var kpkr *C.SignalKyberPreKeyRecord
	signalFfiError := C.signal_kyber_pre_key_record_new(&kpkr, C.uint32_t(id), C.uint64_t(timestamp.UnixMilli()), keyPair.ptr, BytesToBuffer(signature))
	runtime.KeepAlive(keyPair)
	runtime.KeepAlive(signature)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapKyberPreKeyRecord(kpkr), nil
}

func DeserializeKyberPreKeyRecord(serialized []byte) (*KyberPreKeyRecord, error) {
	var kpkr *C.SignalKyberPreKeyRecord
	signalFfiError := C.signal_kyber_pre_key_record_deserialize(&kpkr, BytesToBuffer(serialized))
	runtime.KeepAlive(serialized)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapKyberPreKeyRecord(kpkr), nil
}

func (kpkr *KyberPreKeyRecord) Clone() (*KyberPreKeyRecord, error) {
	var cloned *C.SignalKyberPreKeyRecord
	signalFfiError := C.signal_kyber_pre_key_record_clone(&cloned, kpkr.ptr)
	runtime.KeepAlive(kpkr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapKyberPreKeyRecord(cloned), nil
}

func (kpkr *KyberPreKeyRecord) Destroy() error {
	kpkr.CancelFinalizer()
	return wrapError(C.signal_kyber_pre_key_record_destroy(kpkr.ptr))
}

func (kpkr *KyberPreKeyRecord) CancelFinalizer() {
	runtime.SetFinalizer(kpkr, nil)
}

func (kpkr *KyberPreKeyRecord) Serialize() ([]byte, error) {
	var serialized C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_kyber_pre_key_record_serialize(&serialized, kpkr.ptr)
	runtime.KeepAlive(kpkr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(serialized), nil
}

func (kpkr *KyberPreKeyRecord) GetSignature() ([]byte, error) {
	var signature C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_kyber_pre_key_record_get_signature(&signature, kpkr.ptr)
	runtime.KeepAlive(kpkr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(signature), nil
}

func (kpkr *KyberPreKeyRecord) GetID() (uint32, error) {
	var id C.uint32_t
	signalFfiError := C.signal_kyber_pre_key_record_get_id(&id, kpkr.ptr)
	runtime.KeepAlive(kpkr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return uint32(id), nil
}

func (kpkr *KyberPreKeyRecord) GetTimestamp() (time.Time, error) {
	var ts C.uint64_t
	signalFfiError := C.signal_kyber_pre_key_record_get_timestamp(&ts, kpkr.ptr)
	runtime.KeepAlive(kpkr)
	if signalFfiError != nil {
		return time.Time{}, wrapError(signalFfiError)
	}
	return time.UnixMilli(int64(ts)), nil
}

func (kpkr *KyberPreKeyRecord) GetPublicKey() (*KyberPublicKey, error) {
	var pub *C.SignalKyberPublicKey
	signalFfiError := C.signal_kyber_pre_key_record_get_public_key(&pub, kpkr.ptr)
	runtime.KeepAlive(kpkr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapKyberPublicKey(pub), nil
}

func (kpkr *KyberPreKeyRecord) GetSecretKey() (*KyberSecretKey, error) {
	var sec *C.SignalKyberSecretKey
	signalFfiError := C.signal_kyber_pre_key_record_get_secret_key(&sec, kpkr.ptr)
	runtime.KeepAlive(kpkr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapKyberSecretKey(sec), nil
}

func KyberKeyPairGenerate() (*KyberKeyPair, error) {
	var kp *C.SignalKyberKeyPair
	signalFfiError := C.signal_kyber_key_pair_generate(&kp)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapKyberKeyPair(kp), nil
}
