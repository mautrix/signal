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
	"log"
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
		log.Printf("SessionStore: Loading session")
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
		log.Printf("SessionStore: Storing session")
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
