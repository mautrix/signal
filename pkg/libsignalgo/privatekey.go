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
import "runtime"

type PrivateKey struct {
	ptr *C.SignalPrivateKey
}

func wrapPrivateKey(ptr *C.SignalPrivateKey) *PrivateKey {
	privateKey := &PrivateKey{ptr: ptr}
	runtime.SetFinalizer(privateKey, (*PrivateKey).Destroy)
	return privateKey
}

func GeneratePrivateKey() (*PrivateKey, error) {
	var pk *C.SignalPrivateKey
	signalFfiError := C.signal_privatekey_generate(&pk)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPrivateKey(pk), nil
}

func DeserializePrivateKey(keyData []byte) (*PrivateKey, error) {
	var pk *C.SignalPrivateKey
	signalFfiError := C.signal_privatekey_deserialize(&pk, BytesToBuffer(keyData))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPrivateKey(pk), nil
}

func (pk *PrivateKey) Clone() (*PrivateKey, error) {
	var cloned *C.SignalPrivateKey
	signalFfiError := C.signal_privatekey_clone(&cloned, pk.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPrivateKey(cloned), nil
}

func (pk *PrivateKey) Destroy() error {
	return nil // TODO fix this
	//runtime.SetFinalizer(pk, nil)
	//return wrapError(C.signal_privatekey_destroy(pk.ptr))
}

func (pk *PrivateKey) GetPublicKey() (*PublicKey, error) {
	var pub *C.SignalPublicKey
	signalFfiError := C.signal_privatekey_get_public_key(&pub, pk.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPublicKey(pub), nil
}

func (pk *PrivateKey) Serialize() ([]byte, error) {
	var serialized C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_privatekey_serialize(&serialized, pk.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(serialized), nil
}

func (pk *PrivateKey) Sign(message []byte) ([]byte, error) {
	var signed C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_privatekey_sign(&signed, pk.ptr, BytesToBuffer(message))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(signed), nil
}

func (pk *PrivateKey) Agree(publicKey *PublicKey) ([]byte, error) {
	var agreed C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_privatekey_agree(&agreed, pk.ptr, publicKey.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(agreed), nil
}
