package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
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

func (sc *ServerCertificate) GetKeyId() (uint32, error) {
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
