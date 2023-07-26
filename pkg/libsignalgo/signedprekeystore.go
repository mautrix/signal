package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"

typedef const SignalSignedPreKeyRecord const_signed_pre_key_record;

extern int signal_load_signed_pre_key_callback(void *store_ctx, SignalSignedPreKeyRecord **recordp, uint32_t id, void *ctx);
extern int signal_store_signed_pre_key_callback(void *store_ctx, uint32_t id, const_signed_pre_key_record *record, void *ctx);
*/
import "C"
import (
	"context"
	"log"
	"unsafe"

	gopointer "github.com/mattn/go-pointer"
)

type SignedPreKeyStore interface {
	LoadSignedPreKey(id uint32, context context.Context) (*SignedPreKeyRecord, error)
	StoreSignedPreKey(id uint32, signedPreKeyRecord *SignedPreKeyRecord, context context.Context) error
}

//export signal_load_signed_pre_key_callback
func signal_load_signed_pre_key_callback(storeCtx unsafe.Pointer, keyp **C.SignalSignedPreKeyRecord, id C.uint32_t, ctxPtr unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctxPtr, func(store SignedPreKeyStore, ctx context.Context) error {
		key, err := store.LoadSignedPreKey(uint32(id), ctx)
		if err != nil {
			log.Printf("SignedPreKeyStore: Error loading signed prekey: %s", err)
		}
		if key == nil {
			log.Printf("SignedPreKeyStore: Signed prekey not found")
		}
		if err == nil && key != nil {
			*keyp = key.ptr
		}
		return err
	})
}

//export signal_store_signed_pre_key_callback
func signal_store_signed_pre_key_callback(storeCtx unsafe.Pointer, id C.uint32_t, preKeyRecord *C.const_signed_pre_key_record, ctxPtr unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctxPtr, func(store SignedPreKeyStore, ctx context.Context) error {
		log.Printf("SignedPreKeyStore: Storing signed prekey")
		record := SignedPreKeyRecord{ptr: (*C.SignalSignedPreKeyRecord)(unsafe.Pointer(preKeyRecord))}
		cloned, err := record.Clone()
		if err != nil {
			return err
		}
		return store.StoreSignedPreKey(uint32(id), cloned, ctx)
	})
}

func wrapSignedPreKeyStore(store SignedPreKeyStore) *C.SignalSignedPreKeyStore {
	// TODO: This is probably a memory leak
	return &C.SignalSignedPreKeyStore{
		ctx:                  gopointer.Save(store),
		load_signed_pre_key:  C.SignalLoadSignedPreKey(C.signal_load_signed_pre_key_callback),
		store_signed_pre_key: C.SignalStoreSignedPreKey(C.signal_store_signed_pre_key_callback),
	}
}
