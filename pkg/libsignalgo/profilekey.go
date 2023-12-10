package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
#include <stdlib.h>
*/
import "C"
import (
	"crypto/rand"
	"fmt"
	"unsafe"
)

type ProfileKey [C.SignalPROFILE_KEY_LEN]byte
type ProfileKeyCommitment [C.SignalPROFILE_KEY_COMMITMENT_LEN]byte
type ProfileKeyVersion [C.SignalPROFILE_KEY_VERSION_ENCODED_LEN]byte
type AccessKey [C.SignalACCESS_KEY_LEN]byte

func (ak *AccessKey) String() string {
	return string((*ak)[:])
}

func (pv *ProfileKeyVersion) String() string {
	return string((*pv)[:])
}

func (pk *ProfileKey) Slice() []byte {
	return (*pk)[:]
}

func (pk *ProfileKey) GetCommitment(uuid UUID) (*ProfileKeyCommitment, error) {
	c_result := [C.SignalPROFILE_KEY_COMMITMENT_LEN]C.uchar{}
	c_profileKey := (*[C.SignalPROFILE_KEY_LEN]C.uchar)(unsafe.Pointer(pk))
	c_uuid, err := SignalServiceIdFromUUID(uuid)
	if err != nil {
		return nil, err
	}

	signalFfiError := C.signal_profile_key_get_commitment(
		&c_result,
		c_profileKey,
		c_uuid,
	)

	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}

	var result ProfileKeyCommitment
	copy(result[:], C.GoBytes(unsafe.Pointer(&c_result), C.int(C.SignalPROFILE_KEY_COMMITMENT_LEN)))
	return &result, nil
}

func (pk *ProfileKey) GetProfileKeyVersion(uuid UUID) (*ProfileKeyVersion, error) {
	c_result := [C.SignalPROFILE_KEY_VERSION_ENCODED_LEN]C.uchar{}
	c_profileKey := (*[C.SignalPROFILE_KEY_LEN]C.uchar)(unsafe.Pointer(pk))
	c_uuid, err := SignalServiceIdFromUUID(uuid)
	if err != nil {
		return nil, err
	}

	signalFfiError := C.signal_profile_key_get_profile_key_version(
		&c_result,
		c_profileKey,
		c_uuid,
	)

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

	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}

	var result AccessKey
	copy(result[:], C.GoBytes(unsafe.Pointer(&c_result), C.int(C.SignalACCESS_KEY_LEN)))
	return &result, nil
}

func cBytes(b []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

func cLen(b []byte) C.uint32_t {
	return C.uint32_t(len(b))
}

func randBytes(length int) []byte {
	buf := make([]byte, length)
	if n, err := rand.Read(buf); err != nil {
		fmt.Printf("rand.Read() failed: %v\n n: %v\n", err, n)
		panic(err)
	}
	return buf
}

type ProfileKeyCredentialRequestContext [C.SignalPROFILE_KEY_CREDENTIAL_REQUEST_CONTEXT_LEN]byte
type ProfileKeyCredentialRequest [C.SignalPROFILE_KEY_CREDENTIAL_REQUEST_LEN]byte
type ProfileKeyCredentialResponse []byte
type ProfileKeyCredentialPresentation []byte
type ServerPublicParams [C.SignalSERVER_PUBLIC_PARAMS_LEN]byte
type UUID [C.SignalUUID_LEN]byte

func CreateProfileKeyCredentialRequestContext(serverPublicParams ServerPublicParams, uuid UUID, profileKey ProfileKey) (*ProfileKeyCredentialRequestContext, error) {
	c_result := [C.SignalPROFILE_KEY_CREDENTIAL_REQUEST_CONTEXT_LEN]C.uchar{}
	c_serverPublicParams := (*[C.SignalSERVER_PUBLIC_PARAMS_LEN]C.uchar)(unsafe.Pointer(&serverPublicParams[0]))
	random := [32]byte(randBytes(32))
	c_random := (*[32]C.uchar)(unsafe.Pointer(&random[0]))
	c_profileKey := (*[C.SignalPROFILE_KEY_LEN]C.uchar)(unsafe.Pointer(&profileKey[0]))
	c_uuid, err := SignalServiceIdFromUUID(uuid)
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
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	result := ProfileKeyCredentialRequest(C.GoBytes(unsafe.Pointer(&c_result), C.int(C.SignalPROFILE_KEY_CREDENTIAL_REQUEST_LEN)))
	return &result, nil
}

func NewProfileKeyCredentialResponse(b []byte) (ProfileKeyCredentialResponse, error) {
	borrowedBuffer := BytesToBuffer(b)
	signalFfiError := C.signal_expiring_profile_key_credential_response_check_valid_contents(borrowedBuffer)
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
