package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"

typedef const SignalKyberPreKeyRecord const_kyber_pre_key_record;

extern int signal_load_kyber_pre_key_callback(void *store_ctx, SignalKyberPreKeyRecord **recordp, uint32_t id, void *ctx);
extern int signal_store_kyber_pre_key_callback(void *store_ctx, uint32_t id, const_kyber_pre_key_record *record, void *ctx);
extern int signal_mark_kyber_pre_key_used_callback(void *store_ctx, uint32_t id, void *ctx);
*/
import "C"
import (
	"context"
	"unsafe"

	gopointer "github.com/mattn/go-pointer"
)

type KyberPreKeyStore interface {
	LoadKyberPreKey(id uint32, context context.Context) (*KyberPreKeyRecord, error)
	StoreKyberPreKey(id uint32, kyberPreKeyRecord *KyberPreKeyRecord, context context.Context) error
	MarkKyberPreKeyUsed(id uint32, context context.Context) error
}

//export signal_load_kyber_pre_key_callback
func signal_load_kyber_pre_key_callback(storeCtx unsafe.Pointer, keyp **C.SignalKyberPreKeyRecord, id C.uint32_t, ctxPtr unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctxPtr, func(store KyberPreKeyStore, ctx context.Context) error {
		key, err := store.LoadKyberPreKey(uint32(id), ctx)
		if err == nil && key != nil {
			*keyp = key.ptr
		}
		return err
	})
}

//export signal_store_kyber_pre_key_callback
func signal_store_kyber_pre_key_callback(storeCtx unsafe.Pointer, id C.uint32_t, preKeyRecord *C.const_kyber_pre_key_record, ctxPtr unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctxPtr, func(store KyberPreKeyStore, ctx context.Context) error {
		record := KyberPreKeyRecord{ptr: (*C.SignalKyberPreKeyRecord)(unsafe.Pointer(preKeyRecord))}
		cloned, err := record.Clone()
		if err != nil {
			return err
		}
		return store.StoreKyberPreKey(uint32(id), cloned, ctx)
	})
}

//export signal_mark_kyber_pre_key_used_callback
func signal_mark_kyber_pre_key_used_callback(storeCtx unsafe.Pointer, id C.uint32_t, ctxPtr unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctxPtr, func(store KyberPreKeyStore, ctx context.Context) error {
		err := store.MarkKyberPreKeyUsed(uint32(id), ctx)
		return err
	})
}

func wrapKyberPreKeyStore(store KyberPreKeyStore) *C.SignalKyberPreKeyStore {
	// TODO: This is probably a memory leak
	return &C.SignalKyberPreKeyStore{
		ctx:                     gopointer.Save(store),
		load_kyber_pre_key:      C.SignalLoadKyberPreKey(C.signal_load_kyber_pre_key_callback),
		store_kyber_pre_key:     C.SignalStoreKyberPreKey(C.signal_store_kyber_pre_key_callback),
		mark_kyber_pre_key_used: C.SignalMarkKyberPreKeyUsed(C.signal_mark_kyber_pre_key_used_callback),
	}
}
