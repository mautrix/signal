package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
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
	var resp *C.uchar
	var length C.ulong
	signalFfiError := C.signal_hsm_enclave_client_initial_request(&resp, &length, hsm.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(resp, length), nil
}

func (hsm *HSMEnclaveClient) CompleteHandshake(handshakeReceived []byte) error {
	signalFfiError := C.signal_hsm_enclave_client_complete_handshake(hsm.ptr, BytesToBuffer(handshakeReceived))
	return wrapError(signalFfiError)
}

func (hsm *HSMEnclaveClient) EstablishedSend(plaintext []byte) ([]byte, error) {
	var resp *C.uchar
	var length C.ulong
	signalFfiError := C.signal_hsm_enclave_client_established_send(&resp, &length, hsm.ptr, BytesToBuffer(plaintext))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(resp, length), nil
}

func (cds *HSMEnclaveClient) EstablishedReceive(ciphertext []byte) ([]byte, error) {
	var resp *C.uchar
	var length C.ulong
	signalFfiError := C.signal_hsm_enclave_client_established_recv(&resp, &length, cds.ptr, BytesToBuffer(ciphertext))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(resp, length), nil
}
