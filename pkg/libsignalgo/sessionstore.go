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

typedef const SignalSessionRecord const_session_record;
typedef const SignalProtocolAddress const_address;

extern int signal_load_session_callback(void *store_ctx, SignalSessionRecord **recordp, const_address *address, void *ctx);
extern int signal_store_session_callback(void *store_ctx, const_address *address, const_session_record *record, void *ctx);
*/
import "C"
import (
	"context"
	"unsafe"

	gopointer "github.com/mattn/go-pointer"
)

type SessionStore interface {
	LoadSession(address *Address, ctx context.Context) (*SessionRecord, error)
	StoreSession(address *Address, record *SessionRecord, ctx context.Context) error
}

//export signal_load_session_callback
func signal_load_session_callback(storeCtx unsafe.Pointer, recordp **C.SignalSessionRecord, address *C.const_address, ctxPtr unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctxPtr, func(store SessionStore, ctx context.Context) error {
		record, err := store.LoadSession(
			&Address{ptr: (*C.SignalProtocolAddress)(unsafe.Pointer(address))},
			ctx,
		)
		if err == nil && record != nil {
			*recordp = record.ptr
		}
		return err
	})
}

//export signal_store_session_callback
func signal_store_session_callback(storeCtx unsafe.Pointer, address *C.const_address, sessionRecord *C.const_session_record, ctxPtr unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctxPtr, func(store SessionStore, ctx context.Context) error {
		record := SessionRecord{ptr: (*C.SignalSessionRecord)(unsafe.Pointer(sessionRecord))}
		cloned, err := record.Clone()
		if err != nil {
			return err
		}
		return store.StoreSession(
			&Address{ptr: (*C.SignalProtocolAddress)(unsafe.Pointer(address))},
			cloned,
			ctx,
		)
	})
}

func wrapSessionStore(store SessionStore) *C.SignalSessionStore {
	return &C.SignalSessionStore{
		ctx:           gopointer.Save(store),
		load_session:  C.SignalLoadSession(C.signal_load_session_callback),
		store_session: C.SignalStoreSession(C.signal_store_session_callback),
	}
}
