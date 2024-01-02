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

typedef const SignalPreKeyRecord const_pre_key_record;

extern int signal_load_pre_key_callback(void *store_ctx, SignalPreKeyRecord **recordp, uint32_t id, void *ctx);
extern int signal_store_pre_key_callback(void *store_ctx, uint32_t id, const_pre_key_record *record, void *ctx);
extern int signal_remove_pre_key_callback(void *store_ctx, uint32_t id, void *ctx);
*/
import "C"
import (
	"context"
	"unsafe"

	gopointer "github.com/mattn/go-pointer"
)

type PreKeyStore interface {
	LoadPreKey(id uint32, ctx context.Context) (*PreKeyRecord, error)
	StorePreKey(id uint32, preKeyRecord *PreKeyRecord, ctx context.Context) error
	RemovePreKey(id uint32, ctx context.Context) error
}

//export signal_load_pre_key_callback
func signal_load_pre_key_callback(storeCtx unsafe.Pointer, keyp **C.SignalPreKeyRecord, id C.uint32_t, ctxPtr unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctxPtr, func(store PreKeyStore, ctx context.Context) error {
		key, err := store.LoadPreKey(uint32(id), ctx)
		if err == nil && key != nil {
			key.CancelFinalizer()
			*keyp = key.ptr
		}
		return err
	})
}

//export signal_store_pre_key_callback
func signal_store_pre_key_callback(storeCtx unsafe.Pointer, id C.uint32_t, preKeyRecord *C.const_pre_key_record, ctxPtr unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctxPtr, func(store PreKeyStore, ctx context.Context) error {
		record := PreKeyRecord{ptr: (*C.SignalPreKeyRecord)(unsafe.Pointer(preKeyRecord))}
		cloned, err := record.Clone()
		if err != nil {
			return err
		}
		return store.StorePreKey(uint32(id), cloned, ctx)
	})
}

//export signal_remove_pre_key_callback
func signal_remove_pre_key_callback(storeCtx unsafe.Pointer, id C.uint32_t, ctxPtr unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctxPtr, func(store PreKeyStore, ctx context.Context) error {
		return store.RemovePreKey(uint32(id), ctx)
	})
}

func wrapPreKeyStore(store PreKeyStore) *C.SignalPreKeyStore {
	// TODO: This is probably a memory leak
	return &C.SignalPreKeyStore{
		ctx:            gopointer.Save(store),
		load_pre_key:   C.SignalLoadPreKey(C.signal_load_pre_key_callback),
		store_pre_key:  C.SignalStorePreKey(C.signal_store_pre_key_callback),
		remove_pre_key: C.SignalRemovePreKey(C.signal_remove_pre_key_callback),
	}
}
