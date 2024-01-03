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
	"unsafe"

	"github.com/google/uuid"
)

func ProcessSenderKeyDistributionMessage(message *SenderKeyDistributionMessage, fromSender *Address, store SenderKeyStore, ctx *CallbackContext) error {
	signalFfiError := C.signal_process_sender_key_distribution_message(
		fromSender.ptr,
		message.ptr,
		wrapSenderKeyStore(store),
	)
	runtime.KeepAlive(message)
	runtime.KeepAlive(fromSender)
	return wrapCallbackError(signalFfiError, ctx)
}

type SenderKeyDistributionMessage struct {
	nc  noCopy
	ptr *C.SignalSenderKeyDistributionMessage
}

func wrapSenderKeyDistributionMessage(ptr *C.SignalSenderKeyDistributionMessage) *SenderKeyDistributionMessage {
	sc := &SenderKeyDistributionMessage{ptr: ptr}
	runtime.SetFinalizer(sc, (*SenderKeyDistributionMessage).Destroy)
	return sc
}

func NewSenderKeyDistributionMessage(sender *Address, distributionID uuid.UUID, store SenderKeyStore, ctx *CallbackContext) (*SenderKeyDistributionMessage, error) {
	var skdm *C.SignalSenderKeyDistributionMessage
	signalFfiError := C.signal_sender_key_distribution_message_create(
		&skdm,
		sender.ptr,
		(*[C.SignalUUID_LEN]C.uchar)(unsafe.Pointer(&distributionID)),
		wrapSenderKeyStore(store),
	)
	runtime.KeepAlive(sender)
	runtime.KeepAlive(distributionID)
	if signalFfiError != nil {
		return nil, wrapCallbackError(signalFfiError, ctx)
	}
	return wrapSenderKeyDistributionMessage(skdm), nil
}

func DeserializeSenderKeyDistributionMessage(serialized []byte) (*SenderKeyDistributionMessage, error) {
	var skdm *C.SignalSenderKeyDistributionMessage
	signalFfiError := C.signal_sender_key_distribution_message_deserialize(&skdm, BytesToBuffer(serialized))
	runtime.KeepAlive(serialized)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapSenderKeyDistributionMessage(skdm), nil
}

func (sc *SenderKeyDistributionMessage) Destroy() error {
	sc.CancelFinalizer()
	return wrapError(C.signal_sender_key_distribution_message_destroy(sc.ptr))
}

func (sc *SenderKeyDistributionMessage) CancelFinalizer() {
	runtime.SetFinalizer(sc, nil)
}

func (sc *SenderKeyDistributionMessage) Serialize() ([]byte, error) {
	var serialized C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_sender_key_distribution_message_serialize(&serialized, sc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(serialized), nil
}

func (sc *SenderKeyDistributionMessage) Process(sender *Address, store SenderKeyStore, ctx *CallbackContext) error {
	signalFfiError := C.signal_process_sender_key_distribution_message(
		sender.ptr,
		sc.ptr,
		wrapSenderKeyStore(store),
	)
	runtime.KeepAlive(sender)
	if signalFfiError != nil {
		return wrapCallbackError(signalFfiError, ctx)
	}
	return nil
}
