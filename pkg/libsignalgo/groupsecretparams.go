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

type Randomness [32]byte

func GenerateRandomness() (Randomness, error) {
	var randomness [32]byte
	_, err := rand.Read(randomness[:])
	return randomness, err
}

type GroupMasterKey [32]byte

type GroupSecretParams [289]byte

func GenerateGroupSecretParams() (GroupSecretParams, error) {
	randomness, err := GenerateRandomness()
	if err != nil {
		return GroupSecretParams{}, err
	}
	return GenerateGroupSecretParamsWithRandomness(randomness)
}

func GenerateGroupSecretParamsWithRandomness(randomness Randomness) (GroupSecretParams, error) {
	var params [289]C.uchar
	signalFfiError := C.signal_group_secret_params_generate_deterministic(&params, (*[32]C.uint8_t)(unsafe.Pointer(&randomness)))
	if signalFfiError != nil {
		return GroupSecretParams{}, wrapError(signalFfiError)
	}
	var groupSecretParams GroupSecretParams
	copy(groupSecretParams[:], C.GoBytes(unsafe.Pointer(&params), C.int(289)))
	return groupSecretParams, nil
}

func DeriveGroupSecretParamsFromMasterKey(groupMasterKey GroupMasterKey) (GroupSecretParams, error) {
	var params [289]C.uchar
	signalFfiError := C.signal_group_secret_params_derive_from_master_key(&params, (*[32]C.uint8_t)(unsafe.Pointer(&groupMasterKey)))
	if signalFfiError != nil {
		return GroupSecretParams{}, wrapError(signalFfiError)
	}
	var groupSecretParams GroupSecretParams
	copy(groupSecretParams[:], C.GoBytes(unsafe.Pointer(&params), C.int(289)))
	return groupSecretParams, nil
}