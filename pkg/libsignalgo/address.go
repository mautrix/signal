package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import (
	"runtime"
)

type Address struct {
	ptr *C.SignalProtocolAddress
}

func wrapAddress(ptr *C.SignalProtocolAddress) *Address {
	address := &Address{ptr: ptr}
	runtime.SetFinalizer(address, (*Address).Destroy)
	return address
}

func NewAddress(name string, deviceID uint) (*Address, error) {
	var pa *C.SignalProtocolAddress
	signalFfiError := C.signal_address_new(&pa, C.CString(name), C.uint(deviceID))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapAddress(pa), nil
}

func (pk *Address) Clone() (*Address, error) {
	var cloned *C.SignalProtocolAddress
	signalFfiError := C.signal_address_clone(&cloned, pk.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapAddress(cloned), nil
}

func (pa *Address) Destroy() error {
	runtime.SetFinalizer(pa, nil)
	return wrapError(C.signal_address_destroy(pa.ptr))
}

func (pa *Address) Name() (string, error) {
	var name *C.char
	signalFfiError := C.signal_address_get_name(&name, pa.ptr)
	if signalFfiError != nil {
		return "", wrapError(signalFfiError)
	}
	return CopyCStringToString(name), nil
}

func (pa *Address) DeviceID() (uint, error) {
	var deviceID C.uint
	signalFfiError := C.signal_address_get_device_id(&deviceID, pa.ptr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return uint(deviceID), nil
}
