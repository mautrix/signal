package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"

typedef const SignalProtocolAddress const_address;

typedef const SignalSenderKeyRecord const_sender_key_record;
typedef const uint8_t const_uuid_bytes[16];

extern int signal_load_sender_key_callback(void *store_ctx, SignalSenderKeyRecord**, const_address*, const_uuid_bytes*, void *ctx);
extern int signal_store_sender_key_callback(void *store_ctx, const_address*, const_uuid_bytes*, const_sender_key_record*, void *ctx);
*/
import "C"
import (
	"context"
	"unsafe"

	"github.com/google/uuid"
	gopointer "github.com/mattn/go-pointer"
)

type SenderKeyStore interface {
	LoadSenderKey(sender Address, distributionID uuid.UUID, ctx context.Context) (*SenderKeyRecord, error)
	StoreSenderKey(sender Address, distributionID uuid.UUID, record *SenderKeyRecord, ctx context.Context) error
}

func wrapSenderKeyStore(store SenderKeyStore) *C.SignalSenderKeyStore {
	// TODO this is probably a memory leak since I'm never getting rid of the
	// saved pointer.
	return &C.SignalSenderKeyStore{
		ctx:              gopointer.Save(store),
		load_sender_key:  C.SignalLoadSenderKey(C.signal_load_sender_key_callback),
		store_sender_key: C.SignalStoreSenderKey(C.signal_store_sender_key_callback),
	}
}

//export signal_load_sender_key_callback
func signal_load_sender_key_callback(storeCtx unsafe.Pointer, recordp **C.SignalSenderKeyRecord, address *C.const_address, distributionIDBytes *C.const_uuid_bytes, ctxPtr unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctxPtr, func(store SenderKeyStore, ctx context.Context) error {
		distributionID := uuid.UUID(*(*[16]byte)(unsafe.Pointer(distributionIDBytes)))
		record, err := store.LoadSenderKey(
			Address{ptr: (*C.SignalProtocolAddress)(unsafe.Pointer(address))},
			distributionID,
			ctx,
		)
		if err == nil && record != nil {
			*recordp = record.ptr
		}
		return err
	})
}

//export signal_store_sender_key_callback
func signal_store_sender_key_callback(storeCtx unsafe.Pointer, address *C.const_address, distributionIDBytes *C.const_uuid_bytes, senderKeyRecord *C.const_sender_key_record, ctxPtr unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctxPtr, func(store SenderKeyStore, ctx context.Context) error {
		distributionID := uuid.UUID(*(*[16]byte)(unsafe.Pointer(distributionIDBytes)))
		record := SenderKeyRecord{ptr: (*C.SignalSenderKeyRecord)(unsafe.Pointer(senderKeyRecord))}
		cloned, err := record.Clone()
		if err != nil {
			return err
		}

		return store.StoreSenderKey(
			Address{ptr: (*C.SignalProtocolAddress)(unsafe.Pointer(address))},
			distributionID,
			cloned,
			ctx,
		)
	})
}
