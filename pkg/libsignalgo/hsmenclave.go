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
