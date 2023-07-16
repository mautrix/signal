package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import (
	"crypto/rand"
	"unsafe"
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
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	var groupPublicParams GroupPublicParams
	copy(groupPublicParams[:], C.GoBytes(unsafe.Pointer(&publicParams), C.int(C.SignalGROUP_PUBLIC_PARAMS_LEN)))
	return &groupPublicParams, nil
}
