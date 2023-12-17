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
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import "runtime"

type HSMEnclaveClient struct {
	ptr *C.SignalHsmEnclaveClient
}

func wrapHSMEnclaveClient(ptr *C.SignalHsmEnclaveClient) *HSMEnclaveClient {
	hsmEnclaveClient := &HSMEnclaveClient{ptr: ptr}
	runtime.SetFinalizer(hsmEnclaveClient, (*HSMEnclaveClient).Destroy)
	return hsmEnclaveClient
}

func NewHSMEnclaveClient(trustedPublicKey, trustedCodeHashes []byte) (*HSMEnclaveClient, error) {
	var cds *C.SignalHsmEnclaveClient
	signalFfiError := C.signal_hsm_enclave_client_new(&cds, BytesToBuffer(trustedPublicKey), BytesToBuffer(trustedCodeHashes))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapHSMEnclaveClient(cds), nil
}

func (hsm *HSMEnclaveClient) Destroy() error {
	runtime.SetFinalizer(hsm, nil)
	return wrapError(C.signal_hsm_enclave_client_destroy(hsm.ptr))
}

func (hsm *HSMEnclaveClient) InitialRequest() ([]byte, error) {
	var resp C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_hsm_enclave_client_initial_request(&resp, hsm.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(resp), nil
}

func (hsm *HSMEnclaveClient) CompleteHandshake(handshakeReceived []byte) error {
	signalFfiError := C.signal_hsm_enclave_client_complete_handshake(hsm.ptr, BytesToBuffer(handshakeReceived))
	return wrapError(signalFfiError)
}

func (hsm *HSMEnclaveClient) EstablishedSend(plaintext []byte) ([]byte, error) {
	var resp C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_hsm_enclave_client_established_send(&resp, hsm.ptr, BytesToBuffer(plaintext))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(resp), nil
}

func (cds *HSMEnclaveClient) EstablishedReceive(ciphertext []byte) ([]byte, error) {
	var resp C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_hsm_enclave_client_established_recv(&resp, cds.ptr, BytesToBuffer(ciphertext))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(resp), nil
}
