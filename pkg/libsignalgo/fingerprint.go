package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import "runtime"

type FingerprintVersion uint32

const (
	FingerprintVersionV1 FingerprintVersion = 1
	FingerprintVersionV2 FingerprintVersion = 2
)

type Fingerprint struct {
	ptr *C.SignalFingerprint
}

func wrapFingerprint(ptr *C.SignalFingerprint) *Fingerprint {
	fingerprint := &Fingerprint{ptr: ptr}
	runtime.SetFinalizer(fingerprint, (*Fingerprint).Destroy)
	return fingerprint
}

func NewFingerprint(iterations, version FingerprintVersion, localIdentifier []byte, localKey *PublicKey, remoteIdentifier []byte, remoteKey *PublicKey) (*Fingerprint, error) {
	var pa *C.SignalFingerprint
	signalFfiError := C.signal_fingerprint_new(&pa, C.uint32_t(iterations), C.uint32_t(version), BytesToBuffer(localIdentifier), localKey.ptr, BytesToBuffer(remoteIdentifier), remoteKey.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapFingerprint(pa), nil
}

func (f *Fingerprint) Clone() (*Fingerprint, error) {
	var cloned *C.SignalFingerprint
	signalFfiError := C.signal_fingerprint_clone(&cloned, f.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapFingerprint(cloned), nil
}

func (f *Fingerprint) Destroy() error {
	runtime.SetFinalizer(f, nil)
	return wrapError(C.signal_fingerprint_destroy(f.ptr))
}

func (f *Fingerprint) ScannableEncoding() ([]byte, error) {
	var scannableEncoding *C.uchar
	var length C.ulong
	signalFfiError := C.signal_fingerprint_scannable_encoding(&scannableEncoding, &length, f.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(scannableEncoding, length), nil
}

func (f *Fingerprint) DisplayString() (string, error) {
	var displayString *C.char
	signalFfiError := C.signal_fingerprint_display_string(&displayString, f.ptr)
	if signalFfiError != nil {
		return "", wrapError(signalFfiError)
	}
	return CopyCStringToString(displayString), nil
}

func (k *Fingerprint) Compare(fingerprint1, fingerprint2 []byte) (bool, error) {
	var compare C.bool
	signalFfiError := C.signal_fingerprint_compare(&compare, BytesToBuffer(fingerprint1), BytesToBuffer(fingerprint2))
	if signalFfiError != nil {
		return false, wrapError(signalFfiError)
	}
	return bool(compare), nil
}
