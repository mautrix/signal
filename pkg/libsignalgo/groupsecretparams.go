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
	"crypto/rand"
	"runtime"
	"unsafe"

	"github.com/google/uuid"
)

type Randomness [C.SignalRANDOMNESS_LEN]byte

func GenerateRandomness() (Randomness, error) {
	var randomness Randomness
	_, err := rand.Read(randomness[:])
	return randomness, err
}

type GroupMasterKey [C.SignalGROUP_MASTER_KEY_LEN]byte
type GroupSecretParams [C.SignalGROUP_SECRET_PARAMS_LEN]byte
type GroupPublicParams [C.SignalGROUP_PUBLIC_PARAMS_LEN]byte
type GroupIdentifier [C.SignalGROUP_IDENTIFIER_LEN]byte

type UUIDCiphertext [C.SignalUUID_CIPHERTEXT_LEN]byte
type ProfileKeyCiphertext [C.SignalPROFILE_KEY_CIPHERTEXT_LEN]byte

func GenerateGroupSecretParams() (GroupSecretParams, error) {
	randomness, err := GenerateRandomness()
	if err != nil {
		return GroupSecretParams{}, err
	}
	return GenerateGroupSecretParamsWithRandomness(randomness)
}

func GenerateGroupSecretParamsWithRandomness(randomness Randomness) (GroupSecretParams, error) {
	var params [C.SignalGROUP_SECRET_PARAMS_LEN]C.uchar
	signalFfiError := C.signal_group_secret_params_generate_deterministic(&params, (*[C.SignalRANDOMNESS_LEN]C.uint8_t)(unsafe.Pointer(&randomness)))
	runtime.KeepAlive(randomness)
	if signalFfiError != nil {
		return GroupSecretParams{}, wrapError(signalFfiError)
	}
	var groupSecretParams GroupSecretParams
	copy(groupSecretParams[:], C.GoBytes(unsafe.Pointer(&params), C.int(C.SignalGROUP_SECRET_PARAMS_LEN)))
	return groupSecretParams, nil
}

func DeriveGroupSecretParamsFromMasterKey(groupMasterKey GroupMasterKey) (GroupSecretParams, error) {
	var params [C.SignalGROUP_SECRET_PARAMS_LEN]C.uchar
	signalFfiError := C.signal_group_secret_params_derive_from_master_key(&params, (*[C.SignalGROUP_MASTER_KEY_LEN]C.uint8_t)(unsafe.Pointer(&groupMasterKey)))
	runtime.KeepAlive(groupMasterKey)
	if signalFfiError != nil {
		return GroupSecretParams{}, wrapError(signalFfiError)
	}
	var groupSecretParams GroupSecretParams
	copy(groupSecretParams[:], C.GoBytes(unsafe.Pointer(&params), C.int(C.SignalGROUP_SECRET_PARAMS_LEN)))
	return groupSecretParams, nil
}

func (gsp *GroupSecretParams) GetPublicParams() (*GroupPublicParams, error) {
	var publicParams [C.SignalGROUP_PUBLIC_PARAMS_LEN]C.uchar
	signalFfiError := C.signal_group_secret_params_get_public_params(&publicParams, (*[C.SignalGROUP_SECRET_PARAMS_LEN]C.uint8_t)(unsafe.Pointer(gsp)))
	runtime.KeepAlive(gsp)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	var groupPublicParams GroupPublicParams
	copy(groupPublicParams[:], C.GoBytes(unsafe.Pointer(&publicParams), C.int(C.SignalGROUP_PUBLIC_PARAMS_LEN)))
	return &groupPublicParams, nil
}

func GetGroupIdentifier(groupPublicParams GroupPublicParams) (*GroupIdentifier, error) {
	var groupIdentifier [C.SignalGROUP_IDENTIFIER_LEN]C.uchar
	signalFfiError := C.signal_group_public_params_get_group_identifier(&groupIdentifier, (*[C.SignalGROUP_PUBLIC_PARAMS_LEN]C.uint8_t)(unsafe.Pointer(&groupPublicParams)))
	runtime.KeepAlive(groupPublicParams)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	var result GroupIdentifier
	copy(result[:], C.GoBytes(unsafe.Pointer(&groupIdentifier), C.int(C.SignalGROUP_IDENTIFIER_LEN)))
	return &result, nil
}

func (gsp *GroupSecretParams) DecryptBlobWithPadding(blob []byte) ([]byte, error) {
	var plaintext C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	borrowedBlob := BytesToBuffer(blob)
	signalFfiError := C.signal_group_secret_params_decrypt_blob_with_padding(
		&plaintext,
		(*[C.SignalGROUP_SECRET_PARAMS_LEN]C.uint8_t)(unsafe.Pointer(gsp)),
		borrowedBlob,
	)
	runtime.KeepAlive(gsp)
	runtime.KeepAlive(blob)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(plaintext), nil
}

func (gsp *GroupSecretParams) DecryptUUID(ciphertextUUID UUIDCiphertext) (*uuid.UUID, error) {
	u := C.SignalServiceIdFixedWidthBinaryBytes{}
	signalFfiError := C.signal_group_secret_params_decrypt_service_id(
		&u,
		(*[C.SignalGROUP_SECRET_PARAMS_LEN]C.uint8_t)(unsafe.Pointer(gsp)),
		(*[C.SignalUUID_CIPHERTEXT_LEN]C.uint8_t)(unsafe.Pointer(&ciphertextUUID)),
	)
	runtime.KeepAlive(gsp)
	runtime.KeepAlive(ciphertextUUID)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}

	result, err := SignalServiceIDToUUID(&u)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (gsp *GroupSecretParams) DecryptProfileKey(ciphertextProfileKey ProfileKeyCiphertext, u uuid.UUID) (*ProfileKey, error) {
	profileKey := [C.SignalPROFILE_KEY_LEN]C.uchar{}
	serviceId, err := SignalServiceIDFromUUID(u)
	if err != nil {
		return nil, err
	}
	signalFfiError := C.signal_group_secret_params_decrypt_profile_key(
		&profileKey,
		(*[C.SignalGROUP_SECRET_PARAMS_LEN]C.uint8_t)(unsafe.Pointer(gsp)),
		(*[C.SignalPROFILE_KEY_CIPHERTEXT_LEN]C.uint8_t)(unsafe.Pointer(&ciphertextProfileKey)),
		serviceId,
	)
	runtime.KeepAlive(gsp)
	runtime.KeepAlive(ciphertextProfileKey)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	var result ProfileKey
	copy(result[:], C.GoBytes(unsafe.Pointer(&profileKey), C.int(C.SignalPROFILE_KEY_LEN)))
	return &result, nil
}
