// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Scott Weber
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
#include <stdlib.h>
*/
import "C"
import (
	"runtime"
	"unsafe"

	"github.com/google/uuid"
	"go.mau.fi/util/random"
)

type ProfileKey [C.SignalPROFILE_KEY_LEN]byte
type ProfileKeyCommitment [C.SignalPROFILE_KEY_COMMITMENT_LEN]byte
type ProfileKeyVersion [C.SignalPROFILE_KEY_VERSION_ENCODED_LEN]byte
type AccessKey [C.SignalACCESS_KEY_LEN]byte

var blankProfileKey ProfileKey

func (pk *ProfileKey) IsEmpty() bool {
	return pk == nil || *pk == blankProfileKey
}

func (ak *AccessKey) String() string {
	return string(ak[:])
}

func (pv *ProfileKeyVersion) String() string {
	return string(pv[:])
}

func (pk *ProfileKey) Slice() []byte {
	if pk == nil {
		return nil
	}
	return pk[:]
}

func (pk *ProfileKey) GetCommitment(u uuid.UUID) (*ProfileKeyCommitment, error) {
	c_result := [C.SignalPROFILE_KEY_COMMITMENT_LEN]C.uchar{}
	c_profileKey := (*[C.SignalPROFILE_KEY_LEN]C.uchar)(unsafe.Pointer(pk))
	c_uuid, err := SignalServiceIDFromUUID(u)
	if err != nil {
		return nil, err
	}

	signalFfiError := C.signal_profile_key_get_commitment(
		&c_result,
		c_profileKey,
		c_uuid,
	)
	runtime.KeepAlive(pk)
	runtime.KeepAlive(u)

	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}

	var result ProfileKeyCommitment
	copy(result[:], C.GoBytes(unsafe.Pointer(&c_result), C.int(C.SignalPROFILE_KEY_COMMITMENT_LEN)))
	return &result, nil
}

func (pk *ProfileKey) GetProfileKeyVersion(u uuid.UUID) (*ProfileKeyVersion, error) {
	c_result := [C.SignalPROFILE_KEY_VERSION_ENCODED_LEN]C.uchar{}
	c_profileKey := (*[C.SignalPROFILE_KEY_LEN]C.uchar)(unsafe.Pointer(pk))
	c_uuid, err := SignalServiceIDFromUUID(u)
	if err != nil {
		return nil, err
	}

	signalFfiError := C.signal_profile_key_get_profile_key_version(
		&c_result,
		c_profileKey,
		c_uuid,
	)
	runtime.KeepAlive(pk)
	runtime.KeepAlive(u)

	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}

	var result ProfileKeyVersion
	copy(result[:], C.GoBytes(unsafe.Pointer(&c_result), C.int(C.SignalPROFILE_KEY_VERSION_ENCODED_LEN)))
	return &result, nil
}

func (pk *ProfileKey) DeriveAccessKey() (*AccessKey, error) {
	c_result := [C.SignalACCESS_KEY_LEN]C.uchar{}
	c_profileKey := (*[C.SignalPROFILE_KEY_LEN]C.uchar)(unsafe.Pointer(pk))

	signalFfiError := C.signal_profile_key_derive_access_key(
		&c_result,
		c_profileKey,
	)
	runtime.KeepAlive(pk)

	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}

	var result AccessKey
	copy(result[:], C.GoBytes(unsafe.Pointer(&c_result), C.int(C.SignalACCESS_KEY_LEN)))
	return &result, nil
}

type ProfileKeyCredentialRequestContext [C.SignalPROFILE_KEY_CREDENTIAL_REQUEST_CONTEXT_LEN]byte
type ProfileKeyCredentialRequest [C.SignalPROFILE_KEY_CREDENTIAL_REQUEST_LEN]byte
type ProfileKeyCredentialResponse []byte
type ProfileKeyCredentialPresentation []byte
type ServerPublicParams [C.SignalSERVER_PUBLIC_PARAMS_LEN]byte

func CreateProfileKeyCredentialRequestContext(serverPublicParams ServerPublicParams, u uuid.UUID, profileKey ProfileKey) (*ProfileKeyCredentialRequestContext, error) {
	c_result := [C.SignalPROFILE_KEY_CREDENTIAL_REQUEST_CONTEXT_LEN]C.uchar{}
	c_serverPublicParams := (*[C.SignalSERVER_PUBLIC_PARAMS_LEN]C.uchar)(unsafe.Pointer(&serverPublicParams[0]))
	randBytes := [32]byte(random.Bytes(32))
	c_random := (*[32]C.uchar)(unsafe.Pointer(&randBytes[0]))
	c_profileKey := (*[C.SignalPROFILE_KEY_LEN]C.uchar)(unsafe.Pointer(&profileKey[0]))
	c_uuid, err := SignalServiceIDFromUUID(u)
	if err != nil {
		return nil, err
	}

	signalFfiError := C.signal_server_public_params_create_profile_key_credential_request_context_deterministic(
		&c_result,
		c_serverPublicParams,
		c_random,
		c_uuid,
		c_profileKey,
	)
	runtime.KeepAlive(serverPublicParams)
	runtime.KeepAlive(u)
	runtime.KeepAlive(profileKey)
	runtime.KeepAlive(randBytes)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	result := ProfileKeyCredentialRequestContext(C.GoBytes(unsafe.Pointer(&c_result), C.int(C.SignalPROFILE_KEY_CREDENTIAL_REQUEST_CONTEXT_LEN)))
	return &result, nil
}

func (p *ProfileKeyCredentialRequestContext) ProfileKeyCredentialRequestContextGetRequest() (*ProfileKeyCredentialRequest, error) {
	c_result := [C.SignalPROFILE_KEY_CREDENTIAL_REQUEST_LEN]C.uchar{}
	c_context := (*[C.SignalPROFILE_KEY_CREDENTIAL_REQUEST_CONTEXT_LEN]C.uchar)(unsafe.Pointer(p))

	signalFfiError := C.signal_profile_key_credential_request_context_get_request(
		&c_result,
		c_context,
	)
	runtime.KeepAlive(p)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	result := ProfileKeyCredentialRequest(C.GoBytes(unsafe.Pointer(&c_result), C.int(C.SignalPROFILE_KEY_CREDENTIAL_REQUEST_LEN)))
	return &result, nil
}

func NewProfileKeyCredentialResponse(b []byte) (ProfileKeyCredentialResponse, error) {
	borrowedBuffer := BytesToBuffer(b)
	signalFfiError := C.signal_expiring_profile_key_credential_response_check_valid_contents(borrowedBuffer)
	runtime.KeepAlive(b)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return ProfileKeyCredentialResponse(b), nil
}

//func NewProfileKeyCredentialPresentation(b []byte) (ProfileKeyCredentialPresentation, error) {
//	C.signal_profile_key_credential_presentation_check_valid_contents(cBytes(b), cLen(b))
//	if res := C.FFI_ProfileKeyCredentialPresentation_checkValidContents(cBytes(b), cLen(b)); res != C.FFI_RETURN_OK {
//		return nil, errFromCode(res)
//	}
//	return ProfileKeyCredentialPresentation(b), nil
//}
//
//func (a ProfileKeyCredentialPresentation) UUIDCiphertext() ([]byte, error) {
//	out := make([]byte, C.UUID_CIPHERTEXT_LEN)
//	if res := C.FFI_ProfileKeyCredentialPresentation_getUuidCiphertext(cBytes(a), cLen(a), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
//		return nil, errFromCode(res)
//	}
//	return out, nil
//}
//
//func (a ProfileKeyCredentialPresentation) ProfileKeyCiphertext() ([]byte, error) {
//	out := make([]byte, C.PROFILE_KEY_CIPHERTEXT_LEN)
//	if res := C.FFI_ProfileKeyCredentialPresentation_getProfileKeyCiphertext(cBytes(a), cLen(a), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
//		return nil, errFromCode(res)
//	}
//	return out, nil
//}
//
