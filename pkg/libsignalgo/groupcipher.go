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
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import (
	"unsafe"

	"github.com/google/uuid"
	gopointer "github.com/mattn/go-pointer"
)

var UUIDLen = sizeMustMatch(C.SignalUUID_LEN, 16)

func GroupEncrypt(ptext []byte, sender *Address, distributionID uuid.UUID, store SenderKeyStore, ctx *CallbackContext) (*CiphertextMessage, error) {
	contextPointer := gopointer.Save(ctx)
	defer gopointer.Unref(contextPointer)

	var ciphertextMessage *C.SignalCiphertextMessage
	signalFfiError := C.signal_group_encrypt_message(
		&ciphertextMessage,
		sender.ptr,
		(*[C.SignalUUID_LEN]C.uchar)(unsafe.Pointer(&distributionID)),
		BytesToBuffer(ptext),
		wrapSenderKeyStore(store))
	if signalFfiError != nil {
		return nil, wrapCallbackError(signalFfiError, ctx)
	}
	return wrapCiphertextMessage(ciphertextMessage), nil
}

func GroupDecrypt(ctext []byte, sender *Address, store SenderKeyStore, ctx *CallbackContext) ([]byte, error) {
	contextPointer := gopointer.Save(ctx)
	defer gopointer.Unref(contextPointer)

	var resp C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_group_decrypt_message(
		&resp,
		sender.ptr,
		BytesToBuffer(ctext),
		wrapSenderKeyStore(store))
	if signalFfiError != nil {
		return nil, wrapCallbackError(signalFfiError, ctx)
	}
	return CopySignalOwnedBufferToBytes(resp), nil
}
