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
import (
	"runtime"

	"github.com/google/uuid"
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

func (pa *Address) Clone() (*Address, error) {
	var cloned *C.SignalProtocolAddress
	signalFfiError := C.signal_address_clone(&cloned, pa.ptr)
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

func (pa *Address) NameUUID() (uuid.UUID, error) {
	name, err := pa.Name()
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.Parse(name)
}

func (pa *Address) DeviceID() (uint, error) {
	var deviceID C.uint
	signalFfiError := C.signal_address_get_device_id(&deviceID, pa.ptr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return uint(deviceID), nil
}
