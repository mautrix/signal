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

type ServerCertificate struct {
	ptr *C.SignalServerCertificate
}

func wrapServerCertificate(ptr *C.SignalServerCertificate) *ServerCertificate {
	serverCertificate := &ServerCertificate{ptr: ptr}
	runtime.SetFinalizer(serverCertificate, (*ServerCertificate).Destroy)
	return serverCertificate
}

// NewServerCertificate should only be used for testing (at least according to
// the Swift bindings).
func NewServerCertificate(keyID uint32, publicKey *PublicKey, trustRoot *PrivateKey) (*ServerCertificate, error) {
	var serverCertificate *C.SignalServerCertificate
	signalFfiError := C.signal_server_certificate_new(&serverCertificate, C.uint32_t(keyID), publicKey.ptr, trustRoot.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapServerCertificate(serverCertificate), nil
}

func DeserializeServerCertificate(serialized []byte) (*ServerCertificate, error) {
	var serverCertificate *C.SignalServerCertificate
	signalFfiError := C.signal_server_certificate_deserialize(&serverCertificate, BytesToBuffer(serialized))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapServerCertificate(serverCertificate), nil
}

func (sc *ServerCertificate) Clone() (*ServerCertificate, error) {
	var cloned *C.SignalServerCertificate
	signalFfiError := C.signal_server_certificate_clone(&cloned, sc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapServerCertificate(cloned), nil
}

func (sc *ServerCertificate) Destroy() error {
	runtime.SetFinalizer(sc, nil)
	return wrapError(C.signal_server_certificate_destroy(sc.ptr))
}

func (sc *ServerCertificate) Serialize() ([]byte, error) {
	var serialized C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_server_certificate_get_serialized(&serialized, sc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(serialized), nil
}

func (sc *ServerCertificate) GetCertificate() ([]byte, error) {
	var certificate C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_server_certificate_get_certificate(&certificate, sc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(certificate), nil
}

func (sc *ServerCertificate) GetSignature() ([]byte, error) {
	var signature C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_server_certificate_get_signature(&signature, sc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(signature), nil
}

func (sc *ServerCertificate) GetKeyID() (uint32, error) {
	var keyID C.uint32_t
	signalFfiError := C.signal_server_certificate_get_key_id(&keyID, sc.ptr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return uint32(keyID), nil
}

func (sc *ServerCertificate) GetKey() (*PublicKey, error) {
	var key *C.SignalPublicKey
	signalFfiError := C.signal_server_certificate_get_key(&key, sc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPublicKey(key), nil
}
