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

typedef const SignalProtocolAddress const_address;
typedef const SignalPublicKey const_public_key;

extern int signal_get_identity_key_pair_callback(void *store_ctx, SignalPrivateKey **keyp, void *ctx);
extern int signal_get_local_registration_id_callback(void *store_ctx, uint32_t *idp, void *ctx);
extern int signal_save_identity_key_callback(void *store_ctx, const_address *address, const_public_key *public_key, void *ctx);
extern int signal_get_identity_key_callback(void *store_ctx, SignalPublicKey **public_keyp, const_address *address, void *ctx);
extern int signal_is_trusted_identity_callback(void *store_ctx, const_address *address, const_public_key *public_key, unsigned int direction, void *ctx);
*/
import "C"
import (
	"context"
	"unsafe"

	gopointer "github.com/mattn/go-pointer"
)

type SignalDirection uint

const (
	SignalDirectionSending   SignalDirection = 0
	SignalDirectionReceiving SignalDirection = 1
)

type IdentityKeyStore interface {
	GetIdentityKeyPair(ctx context.Context) (*IdentityKeyPair, error)
	GetLocalRegistrationID(ctx context.Context) (uint32, error)
	SaveIdentityKey(address *Address, identityKey *IdentityKey, ctx context.Context) (bool, error)
	GetIdentityKey(address *Address, ctx context.Context) (*IdentityKey, error)
	IsTrustedIdentity(address *Address, identityKey *IdentityKey, direction SignalDirection, ctx context.Context) (bool, error)
}

//export signal_get_identity_key_pair_callback
func signal_get_identity_key_pair_callback(storeCtx unsafe.Pointer, keyp **C.SignalPrivateKey, ctxPtr unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctxPtr, func(store IdentityKeyStore, ctx context.Context) error {
		key, err := store.GetIdentityKeyPair(ctx)
		if err != nil {
			return err
		}
		if key == nil {
			*keyp = nil
		} else {
			clone, err := key.privateKey.Clone()
			if err != nil {
				return err
			}
			*keyp = clone.ptr
		}
		return err
	})
}

//export signal_get_local_registration_id_callback
func signal_get_local_registration_id_callback(storeCtx unsafe.Pointer, idp *C.uint32_t, ctxPtr unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctxPtr, func(store IdentityKeyStore, ctx context.Context) error {
		registrationID, err := store.GetLocalRegistrationID(ctx)
		if err == nil {
			*idp = C.uint32_t(registrationID)
		}
		return err
	})
}

//export signal_save_identity_key_callback
func signal_save_identity_key_callback(storeCtx unsafe.Pointer, address *C.const_address, publicKey *C.const_public_key, ctxPtr unsafe.Pointer) C.int {
	// Can't use wrapStoreCallback, because we don't just return an error value in the int
	store := gopointer.Restore(storeCtx).(IdentityKeyStore)
	ctx := NewEmptyCallbackContext()
	if ctxPtr != nil {
		if restored := gopointer.Restore(ctxPtr); restored != nil {
			ctx = restored.(*CallbackContext)
		}
	}

	publicKeyStruct := PublicKey{ptr: (*C.SignalPublicKey)(unsafe.Pointer(publicKey))}
	cloned, err := publicKeyStruct.Clone()
	if err != nil {
		ctx.Error = err
		return -1
	}
	replaced, err := store.SaveIdentityKey(
		&Address{ptr: (*C.SignalProtocolAddress)(unsafe.Pointer(address))},
		&IdentityKey{cloned},
		ctx.Ctx,
	)
	if err != nil {
		ctx.Error = err
		return -1
	}
	if replaced {
		return 1
	} else {
		return 0
	}
}

//export signal_get_identity_key_callback
func signal_get_identity_key_callback(storeCtx unsafe.Pointer, public_keyp **C.SignalPublicKey, address *C.const_address, ctxPtr unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctxPtr, func(store IdentityKeyStore, ctx context.Context) error {
		key, err := store.GetIdentityKey(
			&Address{ptr: (*C.SignalProtocolAddress)(unsafe.Pointer(address))},
			ctx,
		)
		if err == nil && key != nil {
			*public_keyp = key.publicKey.ptr
		}
		return err
	})
}

//export signal_is_trusted_identity_callback
func signal_is_trusted_identity_callback(storeCtx unsafe.Pointer, address *C.const_address, public_key *C.const_public_key, direction C.uint, ctxPtr unsafe.Pointer) C.int {
	// Can't use wrapStoreCallback, because we don't just return an error value in the int
	store := gopointer.Restore(storeCtx).(IdentityKeyStore)
	ctx := NewEmptyCallbackContext()
	if ctxPtr != nil {
		if restored := gopointer.Restore(ctxPtr); restored != nil {
			ctx = restored.(*CallbackContext)
		}
	}
	trusted, err := store.IsTrustedIdentity(
		&Address{ptr: (*C.SignalProtocolAddress)(unsafe.Pointer(address))},
		&IdentityKey{&PublicKey{ptr: (*C.SignalPublicKey)(unsafe.Pointer(public_key))}},
		SignalDirection(direction),
		ctx.Ctx,
	)
	if err != nil {
		ctx.Error = err
		return -1
	}
	if trusted {
		return 1
	} else {
		return 0
	}
}

func wrapIdentityKeyStore(store IdentityKeyStore) *C.SignalIdentityKeyStore {
	// TODO: This is probably a memory leak
	return &C.SignalIdentityKeyStore{
		ctx:                       gopointer.Save(store),
		get_identity_key_pair:     C.SignalGetIdentityKeyPair(C.signal_get_identity_key_pair_callback),
		get_local_registration_id: C.SignalGetLocalRegistrationId(C.signal_get_local_registration_id_callback),
		save_identity:             C.SignalSaveIdentityKey(C.signal_save_identity_key_callback),
		get_identity:              C.SignalGetIdentityKey(C.signal_get_identity_key_callback),
		is_trusted_identity:       C.SignalIsTrustedIdentity(C.signal_is_trusted_identity_callback),
	}
}
