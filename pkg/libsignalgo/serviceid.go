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
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
#include <stdlib.h>
*/
import "C"
import (
	"unsafe"
)

type UUID [C.SignalUUID_LEN]byte

func SignalServiceIdFromUUID(uuid UUID) (cPNIType, error) {
	var result C.SignalServiceIdFixedWidthBinaryBytes
	signalFfiError := C.signal_service_id_parse_from_service_id_binary(&result, BytesToBuffer(uuid[:]))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return cPNIType(unsafe.Pointer(&result)), nil
}

func SignalPNIServiceIdFromUUID(uuid UUID) (cPNIType, error) {
	var result C.SignalServiceIdFixedWidthBinaryBytes
	// Prepend a 0x01 to the UUID to indicate that it is a PNI UUID
	pniUUID := append([]byte{0x01}, uuid[:]...)
	signalFfiError := C.signal_service_id_parse_from_service_id_binary(&result, BytesToBuffer(pniUUID))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return cPNIType(unsafe.Pointer(&result)), nil
}

func SignalServiceIdToUUID(serviceId *C.SignalServiceIdFixedWidthBinaryBytes) (UUID, error) {
	result := C.SignalOwnedBuffer{}
	serviceIdBytes := cPNIType(unsafe.Pointer(serviceId)) // Hack around gcc bug, not needed for clang
	signalFfiError := C.signal_service_id_service_id_binary(&result, serviceIdBytes)
	if signalFfiError != nil {
		return UUID{}, wrapError(signalFfiError)
	}
	UUIDBytes := CopySignalOwnedBufferToBytes(result)
	var uuid UUID
	copy(uuid[:], UUIDBytes)
	return uuid, nil
}
