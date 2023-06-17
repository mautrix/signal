package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import (
	"errors"
	"unsafe"
)

const ProfileKeySize = 32

type ProfileKey struct {
	contents []byte
}

func NewProfileKey(contents []byte) (*ProfileKey, error) {
	if len(contents) != ProfileKeySize {
		return nil, errors.New("invalid content size")
	}
	return &ProfileKey{contents: contents}, nil
}

func (pk *ProfileKey) GetCommitment(uuid [16]byte) (*[]byte, error) {
	//var result ProfileKeyCommitment
	var result []byte

	errCode := C.signal_profile_key_get_commitment(&result)

	if errCode != 0 {
		return nil, errors.New("C function error in GetCommitment")
	}

	return &result, nil
}

func (pk *ProfileKey) GetProfileKeyVersion(uuid [16]byte) (*[]byte, error) {
	//var result ProfileKeyVersion
	var result []byte

	errCode := C.signal_profile_key_get_profile_key_version((*C.uchar)(unsafe.Pointer(&result)),
		(*C.uchar)(unsafe.Pointer(&pk.contents[0])),
		(*C.uchar)(unsafe.Pointer(&uuid[0])))

	if errCode != 0 {
		return nil, errors.New("C function error in GetProfileKeyVersion")
	}

	return &result, nil
}

// LEFT OFF: trying to build this profile key wrapper, need to get C types right
// once i have this, i can get encrypted profiles (currently in stub.go)
// once i have that, i can fetch number when creating a puppet and satsify foreign key constraint
