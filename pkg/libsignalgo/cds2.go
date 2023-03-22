package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"
import (
	"runtime"
	"time"
)

type CDS2Client struct {
	ptr *C.SignalCds2ClientState
}

func wrapCDS2Client(ptr *C.SignalCds2ClientState) *CDS2Client {
	cds := &CDS2Client{ptr: ptr}
	runtime.SetFinalizer(cds, (*CDS2Client).Destroy)
	return cds
}

func NewCDS2Client(mrenclave, attestation []byte, currentTimestamp time.Time) (*CDS2Client, error) {
	var cds *C.SignalCds2ClientState
	signalFfiError := C.signal_cds2_client_state_new(&cds, BytesToBuffer(mrenclave), BytesToBuffer(attestation), C.uint64_t(currentTimestamp.UnixMilli()))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapCDS2Client(cds), nil
}

func (cds *CDS2Client) Destroy() error {
	runtime.SetFinalizer(cds, nil)
	return wrapError(C.signal_cds2_client_state_destroy(cds.ptr))
}

func (cds *CDS2Client) InitialRequest() ([]byte, error) {
	var resp *C.uchar
	var length C.ulong
	signalFfiError := C.signal_cds2_client_state_initial_request(&resp, &length, cds.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(resp, length), nil
}

func (cds *CDS2Client) CompleteHandshake(handshakeReceived []byte) error {
	signalFfiError := C.signal_cds2_client_state_complete_handshake(cds.ptr, BytesToBuffer(handshakeReceived))
	return wrapError(signalFfiError)
}

func (cds *CDS2Client) EstablishedSend(plaintext []byte) ([]byte, error) {
	var resp *C.uchar
	var length C.ulong
	signalFfiError := C.signal_cds2_client_state_established_send(&resp, &length, cds.ptr, BytesToBuffer(plaintext))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(resp, length), nil
}

func (cds *CDS2Client) EstablishedReceive(ciphertext []byte) ([]byte, error) {
	var resp *C.uchar
	var length C.ulong
	signalFfiError := C.signal_cds2_client_state_established_recv(&resp, &length, cds.ptr, BytesToBuffer(ciphertext))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(resp, length), nil
}
