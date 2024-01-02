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
)

type SenderKeyRecord struct {
	ptr *C.SignalSenderKeyRecord
}

func wrapSenderKeyRecord(ptr *C.SignalSenderKeyRecord) *SenderKeyRecord {
	sc := &SenderKeyRecord{ptr: ptr}
	runtime.SetFinalizer(sc, (*SenderKeyRecord).Destroy)
	return sc
}

func DeserializeSenderKeyRecord(serialized []byte) (*SenderKeyRecord, error) {
	var sc *C.SignalSenderKeyRecord
	signalFfiError := C.signal_sender_key_record_deserialize(&sc, BytesToBuffer(serialized))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapSenderKeyRecord(sc), nil
}

func (skr *SenderKeyRecord) Serialize() ([]byte, error) {
	var serialized C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_sender_key_record_serialize(&serialized, skr.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(serialized), nil
}

func (skr *SenderKeyRecord) Clone() (*SenderKeyRecord, error) {
	var cloned *C.SignalSenderKeyRecord
	signalFfiError := C.signal_sender_key_record_clone(&cloned, skr.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapSenderKeyRecord(cloned), nil
}

func (skr *SenderKeyRecord) Destroy() error {
	return nil
	//runtime.SetFinalizer(skr, nil)
	//return wrapError(C.signal_sender_key_record_destroy(skr.ptr))
}
