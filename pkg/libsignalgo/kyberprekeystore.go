// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Scott Weber
// Copyright (C) 2025 Tulir Asokan
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
#include "./libsignal-ffi.h"

typedef const SignalKyberPreKeyRecord const_kyber_pre_key_record;

extern int signal_load_kyber_pre_key_callback(void *store_ctx, SignalKyberPreKeyRecord **recordp, uint32_t id);
extern int signal_store_kyber_pre_key_callback(void *store_ctx, uint32_t id, const_kyber_pre_key_record *record);
extern int signal_mark_kyber_pre_key_used_callback(void *store_ctx, uint32_t id);
*/
import "C"
import (
	"context"
	"unsafe"
)

type KyberPreKeyStore interface {
	LoadKyberPreKey(ctx context.Context, id uint32) (*KyberPreKeyRecord, error)
	StoreKyberPreKey(ctx context.Context, id uint32, kyberPreKeyRecord *KyberPreKeyRecord) error
	MarkKyberPreKeyUsed(ctx context.Context, id uint32) error
}

//export signal_load_kyber_pre_key_callback
func signal_load_kyber_pre_key_callback(storeCtx unsafe.Pointer, keyp **C.SignalKyberPreKeyRecord, id C.uint32_t) C.int {
	return wrapStoreCallback(storeCtx, func(store KyberPreKeyStore, ctx context.Context) error {
		key, err := store.LoadKyberPreKey(ctx, uint32(id))
		if err == nil && key != nil {
			key.CancelFinalizer()
			*keyp = key.ptr
		}
		return err
	})
}

//export signal_store_kyber_pre_key_callback
func signal_store_kyber_pre_key_callback(storeCtx unsafe.Pointer, id C.uint32_t, preKeyRecord *C.const_kyber_pre_key_record) C.int {
	return wrapStoreCallback(storeCtx, func(store KyberPreKeyStore, ctx context.Context) error {
		record := KyberPreKeyRecord{ptr: (*C.SignalKyberPreKeyRecord)(unsafe.Pointer(preKeyRecord))}
		cloned, err := record.Clone()
		if err != nil {
			return err
		}
		return store.StoreKyberPreKey(ctx, uint32(id), cloned)
	})
}

//export signal_mark_kyber_pre_key_used_callback
func signal_mark_kyber_pre_key_used_callback(storeCtx unsafe.Pointer, id C.uint32_t) C.int {
	return wrapStoreCallback(storeCtx, func(store KyberPreKeyStore, ctx context.Context) error {
		err := store.MarkKyberPreKeyUsed(ctx, uint32(id))
		return err
	})
}

func (ctx *CallbackContext) wrapKyberPreKeyStore(store KyberPreKeyStore) C.SignalConstPointerFfiKyberPreKeyStoreStruct {
	return C.SignalConstPointerFfiKyberPreKeyStoreStruct{&C.SignalKyberPreKeyStore{
		ctx:                     wrapStore(ctx, store),
		load_kyber_pre_key:      C.SignalLoadKyberPreKey(C.signal_load_kyber_pre_key_callback),
		store_kyber_pre_key:     C.SignalStoreKyberPreKey(C.signal_store_kyber_pre_key_callback),
		mark_kyber_pre_key_used: C.SignalMarkKyberPreKeyUsed(C.signal_mark_kyber_pre_key_used_callback),
	}}
}
