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
	"time"
)

type DecryptionErrorMessage struct {
	nc  noCopy
	ptr *C.SignalDecryptionErrorMessage
}

func wrapDecryptionErrorMessage(ptr *C.SignalDecryptionErrorMessage) *DecryptionErrorMessage {
	decryptionErrorMessage := &DecryptionErrorMessage{ptr: ptr}
	runtime.SetFinalizer(decryptionErrorMessage, (*DecryptionErrorMessage).Destroy)
	return decryptionErrorMessage
}

func DeserializeDecryptionErrorMessage(messageBytes []byte) (*DecryptionErrorMessage, error) {
	var dem *C.SignalDecryptionErrorMessage
	signalFfiError := C.signal_decryption_error_message_deserialize(&dem, BytesToBuffer(messageBytes))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapDecryptionErrorMessage(dem), nil
}

func DecryptionErrorMessageForOriginalMessage(originalBytes []byte, originalType uint8, originalTs uint64, originalSenderDeviceID uint) (*DecryptionErrorMessage, error) {
	var dem *C.SignalDecryptionErrorMessage
	signalFfiError := C.signal_decryption_error_message_for_original_message(&dem, BytesToBuffer(originalBytes), C.uint8_t(originalType), C.uint64_t(originalTs), C.uint32_t(originalSenderDeviceID))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapDecryptionErrorMessage(dem), nil
}

func DecryptionErrorMessageFromSerializedContent(serialized []byte) (*DecryptionErrorMessage, error) {
	var dem *C.SignalDecryptionErrorMessage
	signalFfiError := C.signal_decryption_error_message_extract_from_serialized_content(&dem, BytesToBuffer(serialized))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapDecryptionErrorMessage(dem), nil
}

func (dem *DecryptionErrorMessage) Clone() (*DecryptionErrorMessage, error) {
	var cloned *C.SignalDecryptionErrorMessage
	signalFfiError := C.signal_decryption_error_message_clone(&cloned, dem.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapDecryptionErrorMessage(cloned), nil
}

func (dem *DecryptionErrorMessage) Destroy() error {
	runtime.SetFinalizer(dem, nil)
	return wrapError(C.signal_decryption_error_message_destroy(dem.ptr))
}

func (dem *DecryptionErrorMessage) Serialize() ([]byte, error) {
	var serialized C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_decryption_error_message_serialize(&serialized, dem.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(serialized), nil
}

func (dem *DecryptionErrorMessage) GetTimestamp() (time.Time, error) {
	var ts C.uint64_t
	signalFfiError := C.signal_decryption_error_message_get_timestamp(&ts, dem.ptr)
	if signalFfiError != nil {
		return time.Time{}, wrapError(signalFfiError)
	}
	return time.UnixMilli(int64(ts)), nil
}

func (dem *DecryptionErrorMessage) GetDeviceID() (uint32, error) {
	var deviceID C.uint32_t
	signalFfiError := C.signal_decryption_error_message_get_device_id(&deviceID, dem.ptr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return uint32(deviceID), nil
}

func (dem *DecryptionErrorMessage) GetRatchetKey() (*PublicKey, error) {
	var pk *C.SignalPublicKey
	signalFfiError := C.signal_decryption_error_message_get_ratchet_key(&pk, dem.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapPublicKey(pk), nil
}
