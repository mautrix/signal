package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"

type DeviceTransferKey struct {
	privateKey []byte
}

func GenerateDeviceTransferKey() (*DeviceTransferKey, error) {
	var resp C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_device_transfer_generate_private_key(&resp)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return &DeviceTransferKey{privateKey: CopySignalOwnedBufferToBytes(resp)}, nil
}

func (dtk *DeviceTransferKey) PrivateKeyMaterial() []byte {
	return dtk.privateKey
}

func (dtk *DeviceTransferKey) GenerateCertificate(name string, days int) ([]byte, error) {
	var resp C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_device_transfer_generate_certificate(&resp, BytesToBuffer(dtk.privateKey), C.CString(name), C.uint32_t(days))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(resp), nil
}
