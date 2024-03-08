// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Scott Weber
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
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/google/uuid"
)

func init() {
	if C.SignalUUID_LEN != 16 {
		panic("libsignal-ffi uuid type size mismatch")
	}
}

func SignalServiceIDFromUUID(uuid uuid.UUID) (cPNIType, error) {
	var result C.SignalServiceIdFixedWidthBinaryBytes
	signalFfiError := C.signal_service_id_parse_from_service_id_binary(&result, BytesToBuffer(uuid[:]))
	runtime.KeepAlive(uuid)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return cPNIType(unsafe.Pointer(&result)), nil
}

func SignalPNIServiceIDFromUUID(uuid uuid.UUID) (cPNIType, error) {
	var result C.SignalServiceIdFixedWidthBinaryBytes
	// Prepend a 0x01 to the UUID to indicate that it is a PNI UUID
	pniUUID := append([]byte{0x01}, uuid[:]...)
	signalFfiError := C.signal_service_id_parse_from_service_id_binary(&result, BytesToBuffer(pniUUID))
	runtime.KeepAlive(pniUUID)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return cPNIType(unsafe.Pointer(&result)), nil
}

func SignalServiceIDToUUID(serviceId *C.SignalServiceIdFixedWidthBinaryBytes) (uuid.UUID, error) {
	result := C.SignalOwnedBuffer{}
	serviceIdBytes := cPNIType(unsafe.Pointer(serviceId)) // Hack around gcc bug, not needed for clang
	signalFfiError := C.signal_service_id_service_id_binary(&result, serviceIdBytes)
	if signalFfiError != nil {
		return uuid.UUID{}, wrapError(signalFfiError)
	}
	uuidBytes := CopySignalOwnedBufferToBytes(result)
	if len(uuidBytes) != 16 {
		return uuid.UUID{}, fmt.Errorf("invalid UUID length: %d. UUID: %x", len(uuidBytes), uuidBytes)
	}
	return uuid.UUID(uuidBytes), nil
}
