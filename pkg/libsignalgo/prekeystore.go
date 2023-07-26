package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"

typedef const SignalPreKeyRecord const_pre_key_record;

extern int signal_load_pre_key_callback(void *store_ctx, SignalPreKeyRecord **recordp, uint32_t id, void *ctx);
extern int signal_store_pre_key_callback(void *store_ctx, uint32_t id, const_pre_key_record *record, void *ctx);
extern int signal_remove_pre_key_callback(void *store_ctx, uint32_t id, void *ctx);
*/
import "C"
import (
	"context"
	"log"
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
		log.Printf("PreKeyStore: Loading prekey %d", id)
		key, err := store.LoadPreKey(uint32(id), ctx)
		if err != nil {
			log.Printf("PreKeyStore: Error loading prekey: %s", err)
		}
		if key == nil {
			log.Printf("PreKeyStore: Prekey not found")
		}
		if err == nil && key != nil {
			*keyp = key.ptr
		}
		return err
	})
}

//export signal_store_pre_key_callback
func signal_store_pre_key_callback(storeCtx unsafe.Pointer, id C.uint32_t, preKeyRecord *C.const_pre_key_record, ctxPtr unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctxPtr, func(store PreKeyStore, ctx context.Context) error {
		log.Printf("PreKeyStore: Storing prekey %d", id)
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
		log.Printf("PreKeyStore: Removing prekey %d", id)
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
