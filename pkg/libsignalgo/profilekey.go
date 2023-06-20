package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
#include <stdlib.h>
*/
import "C"
import (
	"unsafe"
)

type ProfileKey [C.SignalPROFILE_KEY_LEN]byte
type ProfileKeyCommitment [C.SignalPROFILE_KEY_COMMITMENT_LEN]byte
type ProfileKeyVersion [C.SignalPROFILE_KEY_VERSION_ENCODED_LEN]byte
type AccessKey [C.SignalACCESS_KEY_LEN]byte

func (pk *ProfileKey) GetCommitment(uuid [16]byte) (*ProfileKeyCommitment, error) {
	c_result := [C.SignalPROFILE_KEY_COMMITMENT_LEN]C.uchar{}
	c_profileKey := (*[C.SignalPROFILE_KEY_LEN]C.uchar)(unsafe.Pointer(pk))
	c_uuid := (*[16]C.uint8_t)(unsafe.Pointer(&uuid))

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

func (pk *ProfileKey) GetProfileKeyVersion(uuid [16]byte) (*ProfileKeyVersion, error) {
	c_result := [C.SignalPROFILE_KEY_VERSION_ENCODED_LEN]C.uchar{}
	c_profileKey := (*[C.SignalPROFILE_KEY_LEN]C.uchar)(unsafe.Pointer(pk))
	c_uuid := (*[16]C.uint8_t)(unsafe.Pointer(&uuid))

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
