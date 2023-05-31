package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"

type IdentityKey struct {
	publicKey *PublicKey
}

func NewIdentityKeyFromPublicKey(publicKey *PublicKey) (*IdentityKey, error) {
	return &IdentityKey{publicKey: publicKey}, nil
}

func NewIdentityKeyFromBytes(bytes []byte) (*IdentityKey, error) {
	publicKey, err := DeserializePublicKey(bytes)
	if err != nil {
		return nil, err
	}
	return &IdentityKey{publicKey: publicKey}, nil
}

func (i *IdentityKey) Serialize() ([]byte, error) {
	return i.publicKey.Serialize()
}

func DeserializeIdentityKey(bytes []byte) (*IdentityKey, error) {
	var publicKey *C.SignalPublicKey
	signalFfiError := C.signal_publickey_deserialize(&publicKey, BytesToBuffer(bytes))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return &IdentityKey{publicKey: wrapPublicKey(publicKey)}, nil
}

func (i *IdentityKey) VerifyAlternateIdentity(other *IdentityKey, signature []byte) (bool, error) {
	var verify C.bool
	signalFfiError := C.signal_identitykey_verify_alternate_identity(&verify, i.publicKey.ptr, other.publicKey.ptr, BytesToBuffer(signature))
	if signalFfiError != nil {
		return false, wrapError(signalFfiError)
	}
	return bool(verify), nil
}

func (i *IdentityKey) Equal(other *IdentityKey) (bool, error) {
	result, err := i.publicKey.Compare(other.publicKey)
	return result == 0, err
}

type IdentityKeyPair struct {
	publicKey  *PublicKey
	privateKey *PrivateKey
}

func (i *IdentityKeyPair) GetPublicKey() *PublicKey {
	return i.publicKey
}

func (i *IdentityKeyPair) GetPrivateKey() *PrivateKey {
	return i.privateKey
}

func GenerateIdentityKeyPair() (*IdentityKeyPair, error) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	publicKey, err := privateKey.GetPublicKey()
	if err != nil {
		return nil, err
	}
	return &IdentityKeyPair{publicKey: publicKey, privateKey: privateKey}, nil
}

func DeserializeIdentityKeyPair(bytes []byte) (*IdentityKeyPair, error) {
	var privateKey *C.SignalPrivateKey
	var publicKey *C.SignalPublicKey
	signalFfiError := C.signal_identitykeypair_deserialize(&privateKey, &publicKey, BytesToBuffer(bytes))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return &IdentityKeyPair{publicKey: wrapPublicKey(publicKey), privateKey: wrapPrivateKey(privateKey)}, nil
}

func NewIdentityKeyPair(publicKey *PublicKey, privateKey *PrivateKey) (*IdentityKeyPair, error) {
	return &IdentityKeyPair{publicKey: publicKey, privateKey: privateKey}, nil
}

func (i *IdentityKeyPair) Serialize() ([]byte, error) {
	var serialized *C.uchar
	var length C.ulong
	signalFfiError := C.signal_identitykeypair_serialize(&serialized, &length, i.publicKey.ptr, i.privateKey.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(serialized, length), nil
}

func (i *IdentityKeyPair) GetIdentityKey() *IdentityKey {
	return &IdentityKey{publicKey: i.publicKey}
}

func (i *IdentityKeyPair) SignAlternateIdentity(other *IdentityKey) ([]byte, error) {
	var signature *C.uchar
	var length C.ulong
	signalFfiError := C.signal_identitykeypair_sign_alternate_identity(&signature, &length, i.publicKey.ptr, i.privateKey.ptr, other.publicKey.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(signature, length), nil
}
