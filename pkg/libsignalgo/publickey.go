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

type PublicKey struct {
	nc  noCopy
	ptr *C.SignalPublicKey
}

func wrapPublicKey(ptr *C.SignalPublicKey) *PublicKey {
	publicKey := &PublicKey{ptr: ptr}
	runtime.SetFinalizer(publicKey, (*PublicKey).Destroy)
	return publicKey
}

func (pk *PublicKey) Clone() (*PublicKey, error) {
	var cloned *C.SignalPublicKey
	signalFfiError := C.signal_publickey_clone(&cloned, pk.ptr)
	runtime.KeepAlive(pk)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPublicKey(cloned), nil
}

func DeserializePublicKey(keyData []byte) (*PublicKey, error) {
	var pk *C.SignalPublicKey
	signalFfiError := C.signal_publickey_deserialize(&pk, BytesToBuffer(keyData))
	runtime.KeepAlive(keyData)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPublicKey(pk), nil
}

func (pk *PublicKey) Serialize() ([]byte, error) {
	var serialized C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_publickey_serialize(&serialized, pk.ptr)
	runtime.KeepAlive(pk)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(serialized), nil
}

func (k *PublicKey) Destroy() error {
	k.CancelFinalizer()
	return wrapError(C.signal_publickey_destroy(k.ptr))
}

func (k *PublicKey) CancelFinalizer() {
	runtime.SetFinalizer(k, nil)
}

func (k *PublicKey) Compare(other *PublicKey) (int, error) {
	var comparison C.int
	signalFfiError := C.signal_publickey_compare(&comparison, k.ptr, other.ptr)
	runtime.KeepAlive(k)
	runtime.KeepAlive(other)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return int(comparison), nil
}

func (k *PublicKey) Bytes() ([]byte, error) {
	var pub C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_publickey_get_public_key_bytes(&pub, k.ptr)
	runtime.KeepAlive(k)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(pub), nil
}

func (k *PublicKey) Verify(message, signature []byte) (bool, error) {
	var verify C.bool
	signalFfiError := C.signal_publickey_verify(&verify, k.ptr, BytesToBuffer(message), BytesToBuffer(signature))
	runtime.KeepAlive(k)
	runtime.KeepAlive(message)
	runtime.KeepAlive(signature)
	if signalFfiError != nil {
		return false, wrapError(signalFfiError)
	}
	return bool(verify), nil
}
